from flask import Flask, jsonify, request, send_file
import subprocess
import re
from datetime import datetime
import os
import time
from tzlocal import get_localzone
import pytz
import threading
import glob
import logging

app = Flask(__name__, static_folder='static')

app.logger.disabled = True
app.config['PROPAGATE_EXCEPTIONS'] = True

log = logging.getLogger('werkzeug')
log.disabled = True

@app.after_request
def after_request(response):
    return response

log = logging.getLogger('werkzeug')
log.disabled = True

# Store adapter state and multi state
adapter_states = {}
multi_state = {}
previous_phies = set()

# Frequency to channel mapping with bandwidth info
FREQ_TO_CHANNEL = {
    2412: {'channel': '1', 'bandwidth': 'HT20'},
    2417: {'channel': '2', 'bandwidth': 'HT20'},
    2422: {'channel': '3', 'bandwidth': 'HT20'},
    2427: {'channel': '4', 'bandwidth': 'HT20'},
    2432: {'channel': '5', 'bandwidth': 'HT20'},
    2437: {'channel': '6', 'bandwidth': 'HT20'},
    2442: {'channel': '7', 'bandwidth': 'HT20'},
    2447: {'channel': '8', 'bandwidth': 'HT20'},
    2452: {'channel': '9', 'bandwidth': 'HT20'},
    2457: {'channel': '10', 'bandwidth': 'HT20'},
    2462: {'channel': '11', 'bandwidth': 'HT20'},
    2467: {'channel': '12', 'bandwidth': 'HT20'},
    2472: {'channel': '13', 'bandwidth': 'HT20'},
    2484: {'channel': '14', 'bandwidth': 'HT20'},

    # 5GHz channels
    5180: {'channel': '36', 'bandwidth': '80MHz'},
    5200: {'channel': '40', 'bandwidth': '80MHz'},
    5220: {'channel': '44', 'bandwidth': '80MHz'},
    5240: {'channel': '48', 'bandwidth': '80MHz'},
    5260: {'channel': '52', 'bandwidth': '80MHz'},
    5280: {'channel': '56', 'bandwidth': '80MHz'},
    5300: {'channel': '60', 'bandwidth': '80MHz'},
    5320: {'channel': '64', 'bandwidth': '80MHz'},
    5500: {'channel': '100', 'bandwidth': '80MHz'},
    5520: {'channel': '104', 'bandwidth': '80MHz'},
    5540: {'channel': '108', 'bandwidth': '80MHz'},
    5560: {'channel': '112', 'bandwidth': '80MHz'},
    5580: {'channel': '116', 'bandwidth': '80MHz'},
    5600: {'channel': '120', 'bandwidth': '80MHz'},
    5620: {'channel': '124', 'bandwidth': '80MHz'},
    5640: {'channel': '128', 'bandwidth': '80MHz'},
    5660: {'channel': '132', 'bandwidth': '80MHz'},
    5680: {'channel': '136', 'bandwidth': '80MHz'},
    5700: {'channel': '140', 'bandwidth': '80MHz'},
    5720: {'channel': '144', 'bandwidth': '80MHz'},
    5745: {'channel': '149', 'bandwidth': '80MHz'},
    5765: {'channel': '153', 'bandwidth': '80MHz'},
    5785: {'channel': '157', 'bandwidth': '80MHz'},
    5805: {'channel': '161', 'bandwidth': '80MHz'},
    5825: {'channel': '165', 'bandwidth': 'HT20'},

    # 6GHz channels
    5955: {'channel': '1', 'bandwidth': '80MHz'},
    5975: {'channel': '5', 'bandwidth': '80MHz'},
    5995: {'channel': '9', 'bandwidth': '80MHz'},
    6015: {'channel': '13', 'bandwidth': '80MHz'},
    6035: {'channel': '17', 'bandwidth': '80MHz'},
    6055: {'channel': '21', 'bandwidth': '80MHz'},
    6075: {'channel': '25', 'bandwidth': '80MHz'},
    6095: {'channel': '29', 'bandwidth': '80MHz'},
    6115: {'channel': '33', 'bandwidth': '80MHz'},
    6135: {'channel': '37', 'bandwidth': '80MHz'},
    6155: {'channel': '41', 'bandwidth': '80MHz'},
    6175: {'channel': '45', 'bandwidth': '80MHz'},
    6195: {'channel': '49', 'bandwidth': '80MHz'},
    6215: {'channel': '53', 'bandwidth': '80MHz'},
    6235: {'channel': '57', 'bandwidth': '80MHz'},
    6255: {'channel': '61', 'bandwidth': '80MHz'},
    6275: {'channel': '65', 'bandwidth': '80MHz'},
    6295: {'channel': '69', 'bandwidth': '80MHz'},
    6315: {'channel': '73', 'bandwidth': '80MHz'},
    6335: {'channel': '77', 'bandwidth': '80MHz'},
    6355: {'channel': '81', 'bandwidth': '80MHz'},
    6375: {'channel': '85', 'bandwidth': '80MHz'},
    6395: {'channel': '89', 'bandwidth': '80MHz'},
    6415: {'channel': '93', 'bandwidth': '80MHz'}
}

# Thread for channel hopping
channel_hopping_threads = {}

def cleanup_specific_session(session):
    try:
        if is_process_running(session):
            subprocess.run(['sudo', 'screen', '-S', session, '-X', 'quit'], capture_output=True, text=True, check=True, timeout=5)
    except Exception:
        pass

def get_interfaces_info():
    result = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=True)
    lines = result.stdout.splitlines()

    interfaces = []
    current_phy = None
    current_iface = None

    for raw in lines:
        line = raw.strip()

        m_phy = re.match(r"^phy#(\d+)", line)
        if m_phy:
            current_phy = f"phy#{m_phy.group(1)}"
            current_iface = None
            continue

        m_iface = re.match(r"^Interface\s+(\S+)$", line)
        if m_iface and current_phy:
            current_iface = m_iface.group(1)
            continue

        m_type = re.match(r"^type\s+(\S+)$", line)
        if m_type and current_phy and current_iface:
            interfaces.append({
                "phy": current_phy,
                "interface": current_iface,
                "type": m_type.group(1)
            })
            current_iface = None

    return interfaces

def get_adapters():
    try:
        interfaces = get_interfaces_info()
        # Only return monitor-mode adapters (ending with 'mon')
        monitor_adapters = [
            i['interface'] for i in interfaces
            if i['phy'] != 'phy#0'
            and i['type'] == 'monitor'
            and i['interface'].startswith('wlan')
            and i['interface'].endswith('mon')
        ]
        return sorted(monitor_adapters)
    except Exception:
        return []

def is_monitor_mode(adapter):
    try:
        interfaces = get_interfaces_info()
        for i in interfaces:
            if i['interface'] == adapter and i['type'] == 'monitor':
                return True
        return False
    except Exception:
        return False

def is_process_running(session_name):
    try:
        cmd = ['sudo', 'screen', '-ls']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return session_name in result.stdout
        return False
    except subprocess.TimeoutExpired:
        return False
    except subprocess.CalledProcessError:
        return False

def channel_hopping_loop(adapter, frequencies, dwell_time):
    while adapter in channel_hopping_threads and channel_hopping_threads[adapter]['running']:
        for freq in frequencies:
            if not (adapter in channel_hopping_threads and channel_hopping_threads[adapter]['running']):
                break

            freq_info = FREQ_TO_CHANNEL.get(int(freq))
            if not freq_info:
                continue

            bandwidth = freq_info['bandwidth']

            cmd = ['sudo', 'iw', 'dev', adapter, 'set', 'freq', str(freq), bandwidth]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass

            time.sleep(dwell_time / 1000.0)

def compute_capture_size(pcap_filename, split_time):
    size_bytes = 0
    if split_time > 0:
        base_no_ext = pcap_filename.rsplit('.', 1)[0]
        files = glob.glob(base_no_ext + '_*.pcap')
        for f in files:
            if os.path.exists(f):
                size_bytes += os.path.getsize(f)
    else:
        if os.path.exists(pcap_filename):
            size_bytes = os.path.getsize(pcap_filename)
    return round(size_bytes / (1024 * 1024), 2)

# ... (all previous code unchanged until build_capture_filter)

def build_capture_filter(selections):
    filters = []

    # Management
    if selections.get('mgt_all', False):
        filters.append('type mgt')
    elif selections.get('mgt_specific', False):
        mgt_sub = []
        if selections.get('beacon', False): mgt_sub.append('subtype beacon')
        if selections.get('probe_req', False): mgt_sub.append('subtype probe-req')
        if selections.get('probe_resp', False): mgt_sub.append('subtype probe-resp')
        if selections.get('auth', False): mgt_sub.append('subtype auth')
        if selections.get('assoc_req', False): mgt_sub.append('subtype assoc-req')
        if selections.get('assoc_resp', False): mgt_sub.append('subtype assoc-resp')
        if selections.get('reassoc_req', False): mgt_sub.append('subtype reassoc-req')
        if selections.get('reassoc_resp', False): mgt_sub.append('subtype reassoc-resp')
        if selections.get('disassoc', False): mgt_sub.append('subtype disassoc')
        if selections.get('deauth', False): mgt_sub.append('subtype deauth')
        if selections.get('atim', False): mgt_sub.append('subtype atim')
        if mgt_sub:
            filters.extend(mgt_sub)
    # if mgt_none → add nothing for management

    # Control
    if selections.get('ctl_all', False):
        filters.append('type ctl')
    elif selections.get('ctl_specific', False):
        ctl_sub = []
        if selections.get('rts', False): ctl_sub.append('subtype rts')
        if selections.get('cts', False): ctl_sub.append('subtype cts')
        if selections.get('ack', False): ctl_sub.append('subtype ack')
        if selections.get('ps_poll', False): ctl_sub.append('subtype ps-poll')
        if selections.get('cf_end', False): ctl_sub.append('subtype cf-end')
        if selections.get('cf_end_ack', False): ctl_sub.append('subtype cf-end-ack')
        if ctl_sub:
            filters.extend(ctl_sub)

    # Data
    if selections.get('data_all', False):
        filters.append('type data')
    elif selections.get('data_specific', False):
        data_sub = []
        if selections.get('eapol', False): data_sub.append('ether proto 0x888e')
        if selections.get('data_cf_ack', False): data_sub.append('subtype data-cf-ack')
        if selections.get('data_cf_poll', False): data_sub.append('subtype data-cf-poll')
        if selections.get('data_cf_ack_poll', False): data_sub.append('subtype data-cf-ack-poll')
        if selections.get('null', False): data_sub.append('subtype null')
        if selections.get('cf_ack', False): data_sub.append('subtype cf-ack')
        if selections.get('cf_poll', False): data_sub.append('subtype cf-poll')
        if selections.get('cf_ack_poll', False): data_sub.append('subtype cf-ack-poll')
        if selections.get('qos_data', False): data_sub.append('subtype qos-data')
        if selections.get('qos_data_cf_ack', False): data_sub.append('subtype qos-data-cf-ack')
        if selections.get('qos_data_cf_poll', False): data_sub.append('subtype qos-data-cf-poll')
        if selections.get('qos_data_cf_ack_poll', False): data_sub.append('subtype qos-data-cf-ack-poll')
        if selections.get('qos_null', False): data_sub.append('subtype qos')
        if selections.get('qos_cf_poll', False): data_sub.append('subtype qos-cf-poll')
        if selections.get('qos_cf_ack_poll', False): data_sub.append('subtype qos-cf-ack-poll')
        if data_sub:
            filters.extend(data_sub)

    return ' or '.join(filters) if filters else ''


def start_capture_func(adapters, filename, split_time, is_multi=False, capture_filter=''):
    if not adapters:
        return {'error': 'No adapters provided'}, 400

    if is_multi:
        if multi_state.get('busy', False):
            cleanup_specific_session('dumpcap_multi')
            pcap_filename = multi_state.get('pcap_file')
            st = multi_state.get('split_time', 0)
            last_size = compute_capture_size(pcap_filename, st) if pcap_filename else 0.0
            multi_state.update({
                'last_pcap_file': pcap_filename,
                'last_split_time': st,
                'last_filesize': last_size,
                'busy': False,
                'adapters': [],
                'pcap_file': None,
                'split_time': 0,
                'filesize': 0.0,
                'capture_filter': ''
            })
    else:
        adapter = adapters[0]
        state = adapter_states.get(adapter, {})
        if state.get('dumpcap_busy', False):
            session = f'dumpcap_{adapter}'
            cleanup_specific_session(session)
            pcap_filename = state.get('pcap_file')
            st = state.get('split_time', 0)
            last_size = compute_capture_size(pcap_filename, st) if pcap_filename else 0.0
            adapter_states[adapter].update({
                'last_pcap_file': pcap_filename,
                'last_split_time': st,
                'last_filesize': last_size,
                'dumpcap_busy': False,
                'pcap_file': None,
                'split_time': 0,
                'filesize': 0.0,
                'capture_filter': ''
            })

    session_name = 'dumpcap_multi' if is_multi else f'dumpcap_{adapters[0]}'

    local_tz = get_localzone()
    local_tz = pytz.timezone(str(local_tz))
    utc_now = datetime.now(pytz.UTC)
    local_now = utc_now.astimezone(local_tz)
    timestamp = local_now.strftime('%Y-%m-%d--%H-%M-%S')
    base_filename = re.sub(r'[^a-zA-Z0-9-_]', '', filename)[:50]
    if not base_filename:
        base_filename = 'capture'
    pcap_base = f'/home/spicy/{timestamp}_{base_filename}'
    pcap_filename = pcap_base + '.pcap'

    try:
        os.makedirs('/home/spicy', exist_ok=True)
        if not split_time:
            with open(pcap_filename, 'wb') as f:
                f.write(b'\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00')
    except (OSError, PermissionError):
        return {'error': 'Cannot write capture file. Check disk space or permissions.'}, 500

    cmd = ['sudo', 'screen', '-dmS', session_name, 'sudo', '-u', 'spicy', 'dumpcap']
    for adapter in adapters:
        cmd.extend(['-i', adapter])
        if capture_filter:
            cmd.extend(['-f', capture_filter])
    cmd.extend(['-w', pcap_filename])
    if split_time:
        cmd.extend(['-b', f'duration:{split_time}'])





    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        time.sleep(2)
        if not is_process_running(session_name):
            return {'error': 'Failed to start capture process.'}, 500
        if is_multi:
            multi_state.update({
                'busy': True,
                'adapters': adapters,
                'pcap_file': pcap_filename,
                'split_time': int(split_time) if split_time else 0,
                'filesize': 0.0,
                'capture_filter': capture_filter
            })
        else:
            adapter = adapters[0]
            adapter_states[adapter].update({
                'dumpcap_busy': True,
                'pcap_file': pcap_filename,
                'split_time': int(split_time) if split_time else 0,
                'filesize': 0.0,
                'status': 'Capturing',
                'capture_filter': capture_filter
            })
        return {
            'message': f'Capturing to {pcap_filename}' + (' (split files)' if split_time else ''),
            'pcap_file': pcap_filename,
            'filesize': 0.0
        }
    except subprocess.TimeoutExpired:
        return {'error': 'Operation timed out'}, 500
    except subprocess.CalledProcessError as e:
        return {'error': f'Failed to start capture: {e.stderr}'}, 500

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/adapters', methods=['GET'])
def adapters():
    global previous_phies
    try:
        interfaces = get_interfaces_info()
        current_phies = {i['phy'] for i in interfaces if i['phy'] != 'phy#0'}

        if current_phies != previous_phies:
            for adapter in list(adapter_states.keys()):
                state = adapter_states.get(adapter, {})
                if state.get('dumpcap_busy', False):
                    session = f'dumpcap_{adapter}'
                    cleanup_specific_session(session)
                    pcap_filename = state.get('pcap_file')
                    st = state.get('split_time', 0)
                    last_size = compute_capture_size(pcap_filename, st) if pcap_filename else 0.0
                    adapter_states[adapter].update({
                        'last_pcap_file': pcap_filename,
                        'last_split_time': st,
                        'last_filesize': last_size,
                        'dumpcap_busy': False,
                        'pcap_file': None,
                        'split_time': 0,
                        'filesize': 0.0,
                        'capture_filter': ''
                    })
            if multi_state.get('busy', False):
                cleanup_specific_session('dumpcap_multi')
                pcap_filename = multi_state.get('pcap_file')
                st = multi_state.get('split_time', 0)
                last_size = compute_capture_size(pcap_filename, st) if pcap_filename else 0.0
                multi_state.update({
                    'last_pcap_file': pcap_filename,
                    'last_split_time': st,
                    'last_filesize': last_size,
                    'busy': False,
                    'adapters': [],
                    'pcap_file': None,
                    'split_time': 0,
                    'filesize': 0.0,
                    'capture_filter': ''
                })

            for adapter in list(channel_hopping_threads.keys()):
                channel_hopping_threads[adapter]['running'] = False
                if channel_hopping_threads[adapter]['thread']:
                    channel_hopping_threads[adapter]['thread'].join(timeout=5)
                del channel_hopping_threads[adapter]
                if adapter in adapter_states:
                    adapter_states[adapter].update({
                        'hopping_active': False,
                        'frequencies': [],
                        'status': 'Enabled' if is_monitor_mode(adapter) else 'Disabled'
                    })

            mon_adapters = [i['interface'] for i in interfaces if i['phy'] != 'phy#0' and i['type'] == 'monitor' and i['interface'].startswith('wlan') and i['interface'].endswith('mon')]
            for ad_mon in mon_adapters:
                try:
                    subprocess.run(['sudo', 'airmon-ng', 'stop', ad_mon], capture_output=True, text=True, check=True, timeout=10)
                    if ad_mon in adapter_states:
                        adapter_states[ad_mon].update({'status': 'Disabled'})
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass

            interfaces = get_interfaces_info()
            non_mon = [i['interface'] for i in interfaces if i['phy'] != 'phy#0' and i['type'] == 'managed' and i['interface'].startswith('wlan') and not i['interface'].endswith('mon') and i['interface'] != 'wlan0']
            for ad in non_mon:
                try:
                    adapter_states[ad] = adapter_states.get(ad, {})
                    subprocess.run(['sudo', 'airmon-ng', 'start', ad], capture_output=True, text=True, check=True, timeout=10)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass
            previous_phies = current_phies

        adapters_list = get_adapters()
        adapter_info = []
        monitor_adapters = []

        for adapter in adapters_list:
            state = adapter_states.get(adapter, {})
            is_monitor = is_monitor_mode(adapter)
            if is_monitor:
                monitor_adapters.append(adapter)

            hopping_active = adapter in channel_hopping_threads and channel_hopping_threads[adapter]['running']
            dumpcap_busy = state.get('dumpcap_busy', False)
            status = 'Disabled'
            if is_monitor:
                status = 'Enabled'
            if hopping_active:
                status = 'Monitoring'
            if dumpcap_busy:
                status = 'Capturing'

            channels = [FREQ_TO_CHANNEL.get(int(freq), {}).get('channel', 'Unknown') for freq in state.get('frequencies', [])]

            adapter_states[adapter] = {
                'frequencies': state.get('frequencies', []),
                'dwell_time': state.get('dwell_time') or state.get('last_dwell_time', 200),
                'hopping_active': hopping_active,
                'dumpcap_busy': dumpcap_busy,
                'pcap_file': state.get('pcap_file', None),
                'split_time': state.get('split_time', 0),
                'filesize': state.get('filesize', 0.0),
                'last_pcap_file': state.get('last_pcap_file', None),
                'last_split_time': state.get('last_split_time', 0),
                'last_filesize': state.get('last_filesize', 0.0),
                'status': status,
                'capture_filter': state.get('capture_filter', '')
            }

            adapter_info.append({
                'name': adapter,
                'monitor': is_monitor,
                'frequencies': adapter_states[adapter]['frequencies'],
                'channels': channels,
                'dwell_time': adapter_states[adapter]['dwell_time'],
                'hopping_active': hopping_active,
                'dumpcap_busy': dumpcap_busy,
                'pcap_file': adapter_states[adapter]['pcap_file'],
                'split_time': adapter_states[adapter]['split_time'],
                'filesize': adapter_states[adapter]['filesize'],
                'last_pcap_file': adapter_states[adapter]['last_pcap_file'],
                'last_split_time': adapter_states[adapter]['last_split_time'],
                'last_filesize': adapter_states[adapter]['last_filesize'],
                'status': status,
                'is_monitor': is_monitor,
                'capture_filter': adapter_states[adapter]['capture_filter']
            })

        multi_possible = len(monitor_adapters) >= 2

        return jsonify({
            'adapters': adapter_info,
            'multi': multi_state,
            'multi_possible': multi_possible
        })
    except Exception:
        return jsonify({'adapters': [], 'multi': {}, 'multi_possible': False})

@app.route('/shutdown', methods=['POST'])
def shutdown():
    try:
        subprocess.run(['sudo', 'poweroff'], check=True)
        return jsonify({'status': 'success'})
    except subprocess.CalledProcessError:
        return jsonify({'status': 'error', 'message': 'Failed'}), 500

@app.route('/monitor_on', methods=['POST'])
def monitor_on():
    data = request.get_json()
    adapter = data.get('adapter')
    if not adapter or not adapter.startswith('wlan') or adapter == 'wlan0':
        return jsonify({'error': 'Invalid adapter'}), 400
    try:
        state = adapter_states.get(adapter, {})
        if state.get('dumpcap_busy', False):
            session = f'dumpcap_{adapter}'
            cleanup_specific_session(session)
            pcap_filename = state.get('pcap_file')
            st = state.get('split_time', 0)
            last_size = compute_capture_size(pcap_filename, st) if pcap_filename else 0.0
            adapter_states[adapter].update({
                'last_pcap_file': pcap_filename,
                'last_split_time': st,
                'last_filesize': last_size,
                'dumpcap_busy': False,
                'pcap_file': None,
                'split_time': 0,
                'filesize': 0.0,
                'capture_filter': ''
            })
        if multi_state.get('busy', False) and adapter in multi_state.get('adapters', []):
            cleanup_specific_session('dumpcap_multi')
            pcap_filename = multi_state.get('pcap_file')
            st = multi_state.get('split_time', 0)
            last_size = compute_capture_size(pcap_filename, st) if pcap_filename else 0.0
            multi_state.update({
                'last_pcap_file': pcap_filename,
                'last_split_time': st,
                'last_filesize': last_size,
                'busy': False,
                'adapters': [],
                'pcap_file': None,
                'split_time': 0,
                'filesize': 0.0,
                'capture_filter': ''
            })
        result = subprocess.run(['sudo', 'airmon-ng', 'start', adapter], capture_output=True, text=True, check=True, timeout=10)
        adapter_states[adapter] = adapter_states.get(adapter, {})
        return jsonify({'message': f'Adapter {adapter} enabled'})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Operation timed out'}), 500
    except subprocess.CalledProcessError:
        return jsonify({'error': 'Failed to enable adapter. Check compatibility.'}), 500

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    data = request.get_json()
    adapter = data.get('adapter')
    frequencies = data.get('frequencies', [])
    dwell_time = data.get('dwell_time')

    if not adapter or not adapter.endswith('mon'):
        return jsonify({'error': 'Adapter must be enabled'}), 400
    if not frequencies or not isinstance(frequencies, list):
        return jsonify({'error': 'Select at least one frequency'}), 400
    try:
        dwell_time = int(dwell_time)
        if dwell_time not in [200, 500, 1000, 5000, 10000, 60000, 300000]:
            return jsonify({'error': 'Invalid dwell time'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid dwell time format'}), 400

    if adapter in channel_hopping_threads:
        channel_hopping_threads[adapter]['running'] = False
        if channel_hopping_threads[adapter]['thread']:
            channel_hopping_threads[adapter]['thread'].join(timeout=5)
        del channel_hopping_threads[adapter]

    valid_frequencies = []
    valid_channels = []
    for freq in frequencies:
        try:
            freq_clean = str(freq).strip()
            freq_int = int(freq_clean)
            if freq_int in FREQ_TO_CHANNEL:
                valid_frequencies.append(freq_clean)
                valid_channels.append(FREQ_TO_CHANNEL[freq_int]['channel'])
        except (ValueError, TypeError):
            pass

    if not valid_frequencies:
        return jsonify({'error': 'No valid frequencies selected'}), 400

    if len(valid_frequencies) == 1:
        freq = valid_frequencies[0]
        bandwidth = FREQ_TO_CHANNEL[int(freq)]['bandwidth']
        cmd = ['sudo', 'iw', 'dev', adapter, 'set', 'freq', freq, bandwidth]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True)
            channel_hopping_threads[adapter] = {'running': True, 'thread': None}
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return jsonify({'error': 'Error setting frequency'}), 500
    else:
        channel_hopping_threads[adapter] = {
            'running': True,
            'thread': threading.Thread(target=channel_hopping_loop, args=(adapter, valid_frequencies, dwell_time))
        }
        channel_hopping_threads[adapter]['thread'].daemon = True
        channel_hopping_threads[adapter]['thread'].start()

    adapter_states[adapter] = adapter_states.get(adapter, {})
    adapter_states[adapter].update({
        'frequencies': valid_frequencies,
        'dwell_time': dwell_time,
        'hopping_active': True,
        'status': 'Monitoring'
    })

    return jsonify({
        'message': f'Monitoring frequencies on {adapter}',
        'channels': valid_channels
    })

@app.route('/start_capture', methods=['POST'])
def start_capture():
    data = request.get_json()
    adapter = data.get('adapter')
    filename = data.get('filename', '').strip()
    split_time = data.get('split_time')
    capture_filter = data.get('capture_filter', '')

    if not adapter or not adapter.endswith('mon'):
        return jsonify({'error': 'Adapter must be enabled'}), 400

    if split_time:
        try:
            split_time = int(split_time)
        except ValueError:
            return jsonify({'error': 'Invalid split time'}), 400

    adapters = [adapter]
    result = start_capture_func(adapters, filename, split_time, is_multi=False, capture_filter=capture_filter)
    if isinstance(result, tuple) and 'error' in result[0]:
        return jsonify(result[0]), result[1]
    return jsonify(result)

@app.route('/start_dumpcap', methods=['POST'])
def start_dumpcap():
    data = request.get_json()
    adapters = data.get('adapters', [])
    filename = data.get('filename', '').strip()
    split_time = data.get('split_time')
    capture_filter = data.get('capture_filter', '')

    if not adapters or not isinstance(adapters, list) or not all(adapter.endswith('mon') for adapter in adapters):
        return jsonify({'error': 'Select at least one enabled adapter'}), 400

    if len(adapters) < 2:
        return jsonify({'error': 'Multi capture requires at least two adapters'}), 400

    if split_time:
        try:
            split_time = int(split_time)
        except ValueError:
            return jsonify({'error': 'Invalid split time'}), 400

    result = start_capture_func(adapters, filename, split_time, is_multi=True, capture_filter=capture_filter)
    if isinstance(result, tuple) and 'error' in result[0]:
        return jsonify(result[0]), result[1]
    return jsonify(result)

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    data = request.get_json()
    adapter = data.get('adapter')
    if not adapter:
        return jsonify({'error': 'Invalid adapter'}), 400

    state = adapter_states.get(adapter, {})
    if not state.get('dumpcap_busy', False):
        return jsonify({'error': 'No active capture session'}), 400

    try:
        session_name = f'dumpcap_{adapter}'
        cleanup_specific_session(session_name)
        pcap_filename = state.get('pcap_file')
        split_time = state.get('split_time', 0)
        last_size = compute_capture_size(pcap_filename, split_time) if pcap_filename else 0.0
        adapter_states[adapter].update({
            'last_pcap_file': pcap_filename,
            'last_split_time': split_time,
            'last_filesize': last_size,
            'dumpcap_busy': False,
            'pcap_file': None,
            'split_time': 0,
            'filesize': 0.0,
            'capture_filter': '',
            'status': 'Monitoring' if adapter_states[adapter].get('hopping_active', False) else ('Enabled' if is_monitor_mode(adapter) else 'Disabled')
        })
        return jsonify({'message': f'Stopped capture on {adapter}'})
    except Exception:
        return jsonify({'error': 'Failed to stop capture.'}), 500

@app.route('/stop_dumpcap', methods=['POST'])
def stop_dumpcap():
    try:
        if not multi_state.get('busy', False):
            return jsonify({'error': 'No active multi capture session'}), 400
        cleanup_specific_session('dumpcap_multi')
        pcap_filename = multi_state.get('pcap_file')
        split_time = multi_state.get('split_time', 0)
        last_size = compute_capture_size(pcap_filename, split_time) if pcap_filename else 0.0
        multi_state.update({
            'last_pcap_file': pcap_filename,
            'last_split_time': split_time,
            'last_filesize': last_size,
            'busy': False,
            'adapters': [],
            'pcap_file': None,
            'split_time': 0,
            'filesize': 0.0,
            'capture_filter': ''
        })
        return jsonify({'message': 'Stopped multi capture'})
    except Exception:
        return jsonify({'error': 'Failed to stop dumpcap.'}), 500

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    data = request.get_json()
    adapter = data.get('adapter')
    if not adapter or not adapter.endswith('mon'):
        return jsonify({'error': 'Invalid adapter'}), 400

    if not adapter_states.get(adapter, {}).get('hopping_active', False):
        return jsonify({'error': 'No active monitoring session'}), 400

    try:
        if adapter in channel_hopping_threads:
            channel_hopping_threads[adapter]['running'] = False
            if channel_hopping_threads[adapter]['thread']:
                channel_hopping_threads[adapter]['thread'].join(timeout=5)
            del channel_hopping_threads[adapter]

        adapter_states[adapter].update({
            'hopping_active': False,
            'frequencies': [],
            'status': 'Enabled',
            'last_dwell_time': adapter_states[adapter].get('dwell_time', 200)
        })
        return jsonify({'message': f'Stopped monitoring on {adapter}'})
    except Exception:
        return jsonify({'error': 'Failed to stop monitoring.'}), 500

@app.route('/filesize', methods=['POST'])
def filesize():
    data = request.get_json()
    adapter = data.get('adapter')
    if adapter == 'multi':
        if not multi_state.get('busy', False):
            return jsonify({'filesize': 0.0})
        pcap_filename = multi_state.get('pcap_file')
        split_time = multi_state.get('split_time', 0)
        size_mb = compute_capture_size(pcap_filename, split_time)
        multi_state['filesize'] = size_mb
        return jsonify({'filesize': size_mb})
    else:
        if not adapter or not adapter.endswith('mon'):
            return jsonify({'error': 'Invalid adapter'}), 400

        state = adapter_states.get(adapter, {})
        if not state.get('dumpcap_busy', False):
            return jsonify({'filesize': 0.0})

        pcap_filename = state.get('pcap_file')
        split_time = state.get('split_time', 0)
        size_mb = compute_capture_size(pcap_filename, split_time)
        state['filesize'] = size_mb
        return jsonify({'filesize': size_mb})

@app.route('/download/<adapter>', methods=['GET'])
def download(adapter):
    if adapter == 'multi':
        pcap_base = multi_state.get('pcap_file') or multi_state.get('last_pcap_file')
        split_time = multi_state.get('split_time', 0) if multi_state.get('busy', False) else multi_state.get('last_split_time', 0)
    else:
        if not adapter or not adapter.endswith('mon'):
            return jsonify({'error': 'Invalid adapter'}), 400

        state = adapter_states.get(adapter, {})
        pcap_base = state.get('pcap_file') or state.get('last_pcap_file')
        split_time = state.get('split_time', 0) if state.get('dumpcap_busy', False) else state.get('last_split_time', 0)

    if not pcap_base:
        return jsonify({'error': 'No capture file available'}), 404

    if split_time:
        files = glob.glob(pcap_base.replace('.pcap', '_*.pcap'))
        if not files:
            return jsonify({'error': 'No split files found'}), 404
        files.sort(key=lambda f: int(f.split('_')[-1].split('.')[0]))
        latest = files[-1]
    else:
        latest = pcap_base
    if not os.path.exists(latest):
        return jsonify({'error': 'Capture file not found'}), 404

    try:
        return send_file(latest, as_attachment=True)
    except OSError:
        return jsonify({'error': 'Failed to download file'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
