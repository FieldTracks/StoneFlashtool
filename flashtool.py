#!/usr/bin/env python3

import argparse
import configparser
import csv
import json
import time
import os
import re
import requests
import signal
import ssl
import struct
import subprocess
import sys
import time
from datetime import datetime
from uuid import getnode as get_mac
from threading import Thread, Lock

import paho.mqtt.client as mqtt
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FirmwareLoader:
    def __init__(self, check_url):
        self.check_url = check_url

        self.version = None
        self.firmware = None
        self.update_firmware()

    @staticmethod
    def download_file(url):
        res = requests.get(url)
        if res.status_code == 200:
            return res.content
        else:
            return None

    @staticmethod
    def version_str_to_num(version_str):
        version_nums = version_str.split('.')
        if len(version_nums) != 3 or not all(s.isdigit() for s in version_nums):
            return None
        return tuple(map(int, version_nums))

    @staticmethod
    def is_version_bigger(v1, v2):
        """Returns True if v1 is bigger than v2, else False.
        """
        return v1[0] > v2[0] or (v1[0] == v2[0] and (v1[1] > v2[1] or (v1[1] == v2[1] and v1[2] > v2[2])))

    def get_current_version(self):
        return self.version

    def get_firmware(self):
        return self.firmware

    def get_info_json(self):
        res = requests.get(self.check_url)
        if res.status_code != 200:
            return None

        try:
            info = res.json()
        except json.JSONDecodeError:
            return None

        if 'version' in info and 'firmware' in info and hasattr(info['firmware'], '__iter__'):
            version = FirmwareLoader.version_str_to_num(info['version'])
            if version is not None:
                info['version'] = version
                return info
        return None

    def update_firmware(self):
        print('Checking for firmware update...')
        info = self.get_info_json()
        if info is None:
            print('Failed to get firmware info!')
            return

        # We just check for unequality here, since we might want to change the currently distributed version to a lower one
        if self.version is not None and info['version'] == self.version:
            print('Firmware up to date')
            return

        print('Downloading new firmware version {}'.format(info['version']))
        fw = {}
        for fw_part in info['firmware']:
            if 'address' in fw_part and 'download' in fw_part:
                fw_file = FirmwareLoader.download_file(fw_part['download'])
                if fw_file is not None:
                    fw[fw_part['address']] = fw_file

        if len(fw) != len(info['firmware']):
            print('Failed to download firmware!')

        self.version = info['version']
        self.firmware = fw
        print('Updated firmware')


class NvsParser:
    def __init__(self):
        pass

    @staticmethod
    def get_nvs_gen_path():
        return os.environ['IDF_PATH'] + '/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py'

    @staticmethod
    def read_bytes_string(data, start_pos):
        nb = len(data)
        for i in range(start_pos, len(data)):
            if data[i] == 0:
                nb = i
                break

        try:
            return data[start_pos:nb].decode('utf-8')
        except UnicodeDecodeError:
            return ''

    @staticmethod
    def decode(nvs_bin):
        """This is a very minimalistic and hacky function for decoding a binary NVS partition.
        It currently only supports string and uint16 as data types.
        """

        nvs_data = {}
        cpos = 0
        while cpos + 64 <= len(nvs_bin):
            if nvs_bin[cpos + 1] == 0xff:
                cpos += 64
                continue
            elif nvs_bin[cpos] == 0x0:
                cpos += 32
                continue
            elif struct.unpack('>H', nvs_bin[cpos+1:cpos+3])[0] == 0x2102:
                key_start = cpos + 8
                key = NvsParser.read_bytes_string(nvs_bin, key_start)
                value_start = cpos + 32
                value = NvsParser.read_bytes_string(nvs_bin, value_start)
                nvs_data[key] = value
                cpos += 64
            elif struct.unpack('>H', nvs_bin[cpos+1:cpos+3])[0] == 0x0201:
                key_start = cpos + 8
                key = NvsParser.read_bytes_string(nvs_bin, key_start)
                value = struct.unpack('<H', nvs_bin[key_start+16:key_start+18])[0]
                nvs_data[key] = value
                cpos += 32
            else:
                print('Can\'t parse NVS data, skipping block...')
                cpos += 32

        return nvs_data

    @staticmethod
    def encode(nvs_data, nvs_size):
        """This method uses an object of the following form as input:
        {
            "wifi_config": {
                "ssid": ("data", "string", "something"),
                "psk": ("data", "string", "something")
            },
            "mqtt_config": {
                "uri": ("data", "string", "something"),
                ...
            }
        }
        The returned string is a path to the generated binary NVS partition.
        """
        nvs_data_file = '/tmp/flashtool_nvsdata'
        nvs_bin_file = '/tmp/flashtool_nvsbin'

        with open(nvs_data_file, 'w') as csv_file:
            fieldnames = ['key', 'type', 'encoding', 'value']
            writer = csv.writer(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            
            for ns, data in nvs_data.items():
                writer.writerow((ns, 'namespace', '', ''))
                for key, val in data.items():
                    writer.writerow((key, *data))

        p = subprocess.Popen([NvsParser.get_nvs_gen_path(), '--input', nvs_data_file, '--output', nvs_bin_file, '--size', nvs_size], stdout=subprocess.DEVNULL)
        p.wait()
        if p.returncode == 0:
            return nvs_bin_file
        else:
            return None

class EspOperations:
    def __init__(self):
        pass

    @staticmethod
    def get_esptool_path():
        return os.environ['IDF_PATH'] + '/components/esptool_py/esptool/esptool.py'

    @staticmethod
    def read_mac(serial_device):
        res = subprocess.run([EspOperations.get_esptool_path(), '--port', serial_device, '--baud', '115200', 'read_mac'], stdout=subprocess.PIPE)
        stdout = res.stdout.decode('utf-8')
        try:
            mac = re.search('MAC: (.{17})\n', stdout).group(1)
            return mac
        except AttributeError:
            return None

    @staticmethod
    def read_flash(serial_device, start_addr, size):
        tmp_file = '/tmp/flashtool_read'
        p = subprocess.Popen([EspOperations.get_esptool_path(), '--port', serial_device, '--baud', '115200', 'read_flash', start_addr, size, tmp_file], stdout=subprocess.DEVNULL)
        p.wait()
        if p.returncode == 0 and os.path.isfile(tmp_file):
            with open(tmp_file, 'rb') as rf:
                buff = rf.read()
            if len(buff) == size:
                return buff
        return None

    @staticmethod
    def write_flash(serial_device, start_addr, file_name):
        p = subprocess.Popen([EspOperations.get_esptool_path(), '--port', serial_device, '--baud', '115200', 'write_flash', start_addr, file_name], stdout=subprocess.DEVNULL)
        p.wait()
        return p.returncode == 0

    @staticmethod
    def read_version(serial_device):
        v_buff = EspOperations.read_flash(serial_device, '0x10030', 32) 
        if v_buff is not None:
            version_str = NvsParser.read_bytes_string(v_buff, 0)
            version_nums = version_str.split('.')
            if len(version_nums) != 3 or not all(s.isdigit() for s in version_nums):
                return None

            return tuple(map(int, version))
        else:
            return None

    @staticmethod
    def read_nvs_data(serial_device):
        nvs_bin = EspOperations.read_flash(serial_device, '0x9000', '0x6000')
        if nvs_bin is None:
            return None

        nvs_data = NvsParser.decode(nvs_bin)
        return nvs_data


class EspDevice:
    """This class is responsible for keeping track of and interacting with connected stones.
    It is not threadsafe. We rely on the fact that the mqtt client uses a single thread here.
    Provided functions are for:
    - Detecting the connected stone, including: mac, firmware version, nvs data
    - Flashing firmware
    - Flashing NVS data
    - Verifying that stone boots successfully
    """

    def __init__(self, device_path, nvs_data, mqtt, fw_loader):
        self.nvs_data = nvs_data
        self.nvs_data_stone = None

        self.device_path = device_path
        self.mqtt = mqtt
        self.fw_loader = fw_loader

        self.status = 'idle'
        self.active_thread = None

        self.mac = None

        # detect plugged in device
        self.do_detect()

    def stop(self):
        pass

    def is_idle(self):
        return self.status == 'idle' and (self.active_thread is None or not self.active_thread.is_alive())

    def get_mac(self):
        return self.mac

    def set_nvs_data_stone(self, data):
        self.nvs_data_stone = data

    def build_nvs(self):
        # hardcoded for now
        STONE_SCAN_INTERVAL = 8
        NVS_PARTITION_SIZE = 24576

        nvs_config = {
            'wifi_config': {
                'ssid': ('data', 'string', self.nvs_data['ssid']),
                'psk': ('data', 'string', self.nvs_data['psk'])
            },
            'mqtt_config': {
                'uri': ('data', 'string', self.nvs_data['uri']),
                'user': ('data', 'string', self.nvs_data['user']),
                'pass': ('data', 'string', self.nvs_data['pass']),
                'cert': ('file', 'string', self.nvs_data['cert'])
            },
            'ble_config': {
                'beacon_major': ('data', 'u16', self.nvs_data_stone['beacon_major']),
                'beacon_minor': ('data', 'u16', self.nvs_data_stone['beacon_minor']),
                'scan_interval': ('data', 'u16', STONE_SCAN_INTERVAL)
            },
            'device_config': {
                'comment': ('data', 'string', self.nvs_data_stone['comment'])
            }
        }
        nvs_bin_path = NvsParser.encode(nvs_config, NVS_PARTITION_SIZE)
        return nvs_bin_path
        

    def do(self, action):
        if not self.is_idle():
            print('Can\'t {}, busy in state {}'.format(action, self.status))
            return
        
        async_func = getattr(self, 'async_{}_thread'.format(action))

        self.status = action
        self.active_thread = Thread(target=async_func)
        self.active_thread.start()

    def do_detect(self):
        self.do('detect')

    def do_flash_all(self):
        self.do('flash_all')

    def do_flash_nvs(self):
        self.do('flash_nvs')

    def do_check_boot(self):
        self.do('check_boot')


    def disconnected(self):
        if self.mac is not None:
            self.mqtt.delete_retained(self.mac)


    def async_detect_thread(self):
        # read MAC address
        self.mac = EspOperations.read_mac(self.device_path)
        if self.mac is None:
            self.status = 'unsupported'
            return

        self.mqtt.publish_detecting(self.mac)


        # TODO: read firmware name here


        # read firmware version
        stone_version = EspOperations.read_version(self.device_path)
        if stone_version is None:
            stone_version = (0, 0, 0)
        version_string = '{}.{}.{}'.format(*stone_version)

        # read NVS data
        stone_nvs_data = EspOperations.read_nvs_data(self.device_path)

        beacon_major = int(stone_nvs_data['beacon_major']) if 'beacon_major' in stone_nvs_data else 0
        beacon_minor = int(stone_nvs_data['beacon_minor']) if 'beacon_minor' in stone_nvs_data else 0
        comment = stone_nvs_data['comment'] if 'comment' in stone_nvs_data else ''

        # prepare flags for the mqtt message
        is_outdated = FirmwareLoader.is_version_bigger(self.fw_loader.get_current_version(), stone_version)
        
        is_wrong_network = False
        for nvs_key, nvs_value in self.nvs_data.items():
            if nvs_key not in stone_nvs_data or nvs_value != stone_nvs_data[nvs_key]:
                is_wrong_network = True
                break

        self.mqtt.publish_connected(self.mac, beacon_major, beacon_minor, comment, version_string, is_outdated, is_wrong_network, False, False)

        # done
        self.status = 'idle'


    def async_flash_all_thread(self):
        # flash firmware
        firmware = self.fw_loader.get_firmware()
        file_path = '/tmp/flashtool_write'
        for addr, fw_bin in firmware.items():
            with open(file_path, 'wb') as wf:
                wf.write(fw_bin)
            EspOperations.write_flash(self.device_path, addr, file_path)

        # flash nvs
        nvs_path = self.build_nvs()
        EspOperations.write_flash(self.device_path, '0x9000', nvs_path)

        # done
        self.status = 'idle'

    def async_flash_nvs_thread(self):
        nvs_path = self.build_nvs()
        EspOperations.write_flash(self.device_path, '0x9000', nvs_path)
        self.status = 'idle'

    def async_check_boot_thread(self):
        print('Check boot not implemented!')
        self.status = 'idle'


class MqttInterface:
    def __init__(self, host, port, cert, insecure, user, passwd, callback):
        self.own_mac = self.get_mac_string()
        self.callback = callback

        self.client = mqtt.Client()
        self.client.username_pw_set(user, passwd)
        if cert is not None:
            self.client.tls_set(cert, tls_version=ssl.PROTOCOL_TLSv1_2)
            if insecure:
                self.client.tls_insecure_set(True)
        self.client.on_message = self.on_message
        self.client.connect(host, port)
        self.delete_all_retained()

    def spin(self):
        self.client.loop_forever()

    def stop(self):
        self.client.disconnect()

    def on_message(self, client, userdata, message):
        topic = message.topic
        payload = message.payload

        if topic == 'flashtool/command':
            try:
                msg = json.loads(payload.decode('utf-8'))
                operation = msg['operation']
                mac = msg['stone']['mac']
                major = msg['stone']['major']
                minor = msg['stone']['minor']
                comment = msg['stone']['comment']
            except (json.JSONDecodeError, KeyError):
                print("Received invalid command: {}".format(payload))

            self.callback(operation, mac, major, minor, comment)

    def publish_detecting(self, stone_mac):
        topic = 'flashtool/status/{}/{}'.format(self.own_mac, stone_mac)
        message = json.dumps({
            'event': 'detecting'
        })
        self.client.publish(topic, payload=message)

    def publish_connected(self, stone_mac, stone_major, stone_minor, stone_comment, stone_version, stone_outdated, stone_wrong_network, stone_unknown_software, stone_writing):
        topic = 'flashtool/status/{}/{}'.format(self.own_mac, stone_mac)
        message = json.dumps({
            'event': 'connected',
            'stone': {
                'major': stone_major,
                'minor': stone_minor,
                'comment': stone_comment,
                'version': stone_version,
                'outdated': stone_outdated,
                'wrong_network': stone_wrong_network,
                'unknown_software': stone_unknown_software,
                'writing': stone_writing
            }
        })
        self.client.publish(topic, payload=message, retain=(event == 'connected'))

    def publish_disconnected(self, stone_mac):
        topic = 'flashtool/status/{}/{}'.format(self.own_mac, stone_mac)
        message = json.dumps({
            'event': 'disconnected'
        })
        self.client.publish(topic, payload=message)

    def delete_retained(self, stone_mac):
        topic = 'flashtool/status/{}/{}'.format(self.own_mac, stone_mac)
        self.client.publish(topic, payload='', retain=True)

    def delete_all_retained(self):
        """Changes the mqtt client's on_message callback temporarily,
        subscribes to all status topics handeled by this flash device
        and deletes all retained messages that are found. After that
        it unsubscribes from the topic again and changes the
        callback back to self.on_message.
        """
        device_topic = 'flashtool/status/{}/'.format(self.own_mac)
        print('Looking for old retained messages in {}'.format(device_topic))
        def del_retained(client, userdata, message):
            if message.topic.startswith(device_topic):
                print('Deleting retained message from {}'.format(message.topic))
                self.delete_retained(message.topic.split('/')[-1])
        self.client.on_message = del_retained
        self.client.subscribe(device_topic + '+')

        # Spin mqtt for 3 seconds
        time_start = int(time.time() * 1000)
        while int(time.time() * 1000) - time_start < 3000:
            self.client.loop(timeout=(3000 - (int(time.time() * 1000) - time_start)) / 1000)

        self.client.unsubscribe(device_topic + '+')
        self.client.on_message = self.on_message
        print('Done looking for old messages')

    @staticmethod
    def get_mac_string():
        mac = get_mac()
        return ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))


class Main(FileSystemEventHandler):
    def __init__(self):
        if len(sys.argv) != 2:
            print('Usage: {} <config file>'.format(sys.argv[0]))
            exit(1)

        # Load config file
        # Falls back to default values if options are missing
        config = configparser.ConfigParser()
        config.read(sys.argv[1])

        print("Starting StoneFlashtool...")

        # Configuration data for stones
        self.nvs_config_data = {
            'ssid': config.get('Stone Config', 'WifiSSID', fallback='StoneNetwork'),
            'psk': config.get('Stone Config', 'WifiPass', fallback=''),
            'uri': config.get('Stone Config', 'MqttHost', fallback='10.0.0.1'),
            'user': config.get('Stone Config', 'MqttUser', fallback='Stone'),
            'pass': config.get('Stone Config', 'MqttPass', fallback=''),
            'cert': config.get('Stone Config', 'MqttCert', fallback='/etc/stoneflashtool/server.pem')
        }

        # Setup the firmware loader and download current firmware
        self.fw_loader = FirmwareLoader(config.get('Firmware', 'FirmwareDownloadURL', fallback='http://localhost/update.json'))

        # Connect to the MQTT broker
        mqtt_host = config.get('MQTT Auth', 'Hostname', fallback='localhost')
        mqtt_port = config.getint('MQTT Auth', 'Port', fallback=1883)
        mqtt_cert = config.get('MQTT Auth', 'CACert', fallback='server.pem')
        mqtt_insecure = config.getboolean('MQTT Auth', 'Insecure', fallback=False)
        mqtt_user = config.get('MQTT Auth', 'Username', fallback='Flashtool')
        mqtt_pass = config.get('MQTT Auth', 'Password', fallback='')
        self.mqtt = MqttInterface(mqtt_host, mqtt_port, mqtt_cert, mqtt_insecure, mqtt_user, mqtt_pass, self.handle_mqtt_command)

        # Maintain a list with connected devices
        self.devices = {}

        # Watch /dev/ttyUSB* with watchdog
        self.observer = Observer()
        self.observer.schedule(self, '/dev', recursive=False)
        self.observer.start()

        # Catch SIGINTs
        signal.signal(signal.SIGINT, self.signal_handler)

        # Watch MQTT for incoming messages
        self.mqtt.spin()

        # Wait for testing
        #input()

    def signal_handler(self, signal, frame):
        print("\rSIGINT")
        self.stop()

    def stop(self):
        print("Stopping StoneFlashtool...")
        if self.observer is not None:
            self.observer.stop()
        self.mqtt.stop()

    def on_any_event(self, event):
        if not event.is_directory and event.src_path.startswith('/dev/ttyUSB'):
            if event.event_type == 'created':
                if event.src_path in self.devices:
                    print('Detected new tty device {}, but it already exists in our database'.format(event.src_path))
                else:
                    print('Device plugged in: {}'.format(event.src_path))
                    self.devices[event.src_path] = EspDevice(event.src_path, self.nvs_config_data, self.mqtt, self.fw_loader)
            elif event.event_type == 'deleted':
                if event.src_path in self.devices:
                    print('Device removed: {}'.format(event.src_path))
                    self.devices[event.src_path].disconnected()
                    del self.devices[event.src_path]

    def handle_mqtt_command(self, operation, mac, major, minor, comment):
        print('Got MQTT command, MAC: {} | command: {}'.format(mac, operation))

        nvs_data_stone = {
            'beacon_major': major,
            'beacon_minor': minor,
            'comment': comment
        }

        for _, device in self.devices.items():
            if device.get_mac() == mac:
                if operation == 'full_flash':
                    device.set_nvs_data_stone(nvs_data_stone)
                    device.do_flash_all()
                elif operation == 'nvs':
                    device.set_nvs_data_stone(nvs_data_stone)
                    device.do_flash_nvs()


if __name__ == '__main__':
    Main()
