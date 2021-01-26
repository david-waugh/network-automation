##########################################
#                                        #
#  Simple Python script to retrieve      #
#  LLDP neighbour information from       #
#  JunOS devices, and update interface   #
#  descriptions.                         #
#                                        #
#  Scripts are designed to be stand-     #
#  alone for "copy, paste, run"s sake'   #
#                                        #
#  "PEP8? Don't know her"                #
#                                        #
##########################################

from jnpr.junos.utils.config import Config
from prettytable import PrettyTable
from jnpr.junos.exception import *
from jnpr.junos import Device
from getpass import getpass
import argparse

__author__ = "David Waugh"
__email__ = "david-waugh@hotmail.com"

def cyan(string):
    print(f'\u001b[36;1m{string}\u001b[0m')

def green(string):
    print(f'\u001b[32;1m{string}\u001b[0m')

def red(string):
    print(f'\u001b[31;1m{string}\u001b[0m')

def parse_args():
    # parse args for CLI user
    parser = argparse.ArgumentParser()
    parser.add_argument('--devices', '-d', 
                        required=True, 
                        nargs="+", 
                        help="Device list")
    parser.add_argument('--username', '-u', 
                        help="Username")
    parser.add_argument('--password', '-p', 
                        help="Password")
    parser.add_argument('--unique_credentials', '-uc', 
                        action="store_true", 
                        help="Flag. Set true if user/pass changes between devices.")
    parser.add_argument('--dryrun', '-dr', 
                        action="store_true", 
                        help="Dryrun. Set true to not perform changes.")
    return parser.parse_args()

def exception_handler(func):
    # cover all exception handling for any failure-prone functions
    # todo: cover errors :- CommitError, ConfigLoadError, ConnectError, ConnectRefusedError, ConnectUnknownHostError, LockError, PermissionError, SwRollbackError, UnlockError
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RpcTimeoutError:
            msg = 'Error: RPC timeout. Confirm connectivity with host and try again.\n'
        except ConnectClosedError:
            msg = 'Error: Connection closed by remote host.\n'
        except ConnectAuthError:
            msg = 'Error: Failed to authenticate with remote host.\n'
        except Exception as e:
            msg = f'Unexpected Exception: {e}\n'
        red(msg) if output_mode else None
        return None
    return wrapper

def get_credentials():
    # allows user to enter credentials at runtime
    username = input('Username: ')
    password = getpass('Password: ')
    return (username, password)

@exception_handler
def create_session(host, user, password):
    # create PyEZ session with host
    return Device(host=host, user=user, password=password).open()

@exception_handler
def get_lldp_information(session):
    # issue <get-lldp-neighbors-information> rpc request
    return session.rpc.get_lldp_neighbors_information()

def parse_lldp_information(lldp_data):
    # parse xml doc from get_lldp_information, build link_state dict
    link_states = {}
    for entry in lldp_data.findall('.//lldp-neighbor-information'):
        local_port = entry.find('./lldp-local-port-id').text
        remote_port = entry.find('./lldp-remote-port-id').text
        remote_device = entry.find('./lldp-remote-system-name').text
        if local_port not in link_states:
            link_states[local_port] = {}
        link_states[local_port][remote_device] = remote_port
    return link_states

def print_lldp_table(host, data):
    # print a pretty table for CLI user
    tbl.clear()
    tbl.field_names = ["Local Device", "Local Interface", "Remote Interface", "Remote Device"]
    for local_port, neighbours in data.items():
        for remote_device, remote_port in neighbours.items():
            tbl.add_row([host, local_port, remote_port, remote_device])
    print(tbl)

def build_descriptions(host, data):
    # build description set commands
    desc_cmds = []
    for local_port, neighbours in data.items():
        desc = f'{host}:{local_port} <> '
        for remote_device, remote_port in neighbours.items():
            desc += f'{remote_port}:{remote_device},'
        desc_cmds.append(f'set interfaces {local_port} description "{desc.strip(",")}"')
    return desc_cmds

@exception_handler
def update_configuration(cmds, session, dryrun=False):
    # loads cmds into memory, diffs, commits/rollbacks depending on dryrun flag
    with Config(session, mode="private") as config_session:
        for cmd in cmds:
            config_session.load(cmd, format='set')
        config_diff = config_session.diff()
        if config_diff is None and output_mode:
            print('\nInterface description is already up-to-date\n')
            return True
        elif config_diff and output_mode:
            print('\nApplying descriptions:') if output_mode else None
            print(config_diff)
        if dryrun:
            config_session.rollback()
            green('Running in Dryrun mode - NOT commiting changes.\n') if output_mode else None
        else:
            config_session.commit()
            green('Successfully applied descriptions.\n') if output_mode else None
    return True

def set_description_based_on_lldp(devices, user='', password='', uc=False, dryrun=False, output=False):
    '''
    Description:
        Function that, when passed a list of devices and authentication information,
        will retrieve and parse LLDP data from JunOS hosts. The respective interface
        will receive a new description based on this data.
    Inputs:
        devices : list|string : List of devices (or string for singular) to run against.
        user    : string      : Username for authentication.
        password: string      : Password for authentication.
        uc      : boolean     : Unique Credentials for each device, script will prompt
                                for login credentials for each device.
        dryrun  : boolean     : Dryrun flag; true means we will not commit any changes.
    Outputs:
        output  : dict        : Dict, two keys: 
                                    succesful_devices - list of devices that
                                                        successfully ran, 
                                    failed_devices    - list of devices that 
                                                        unsuccessfully ran.
    '''
    failed_devices=[]
    if output:
        global output_mode
        global tbl
        output_mode = True
        tbl = PrettyTable()
    for device in list(devices):
        cyan(device.center(80, '=')) if output_mode else None
        print(device) if not output_mode and uc else None

        if uc or not (user and password): # option for unique credentials for each device.
            user, password = get_credentials()

        session = create_session(device, user, password)
        if session is None:
            failed_devices.append(device)
            continue

        lldp_data = get_lldp_information(session)
        if lldp_data is None:
            failed_devices.append(device)
            continue

        link_states = parse_lldp_information(lldp_data)

        if output_mode:
            print_lldp_table(device, link_states)

        rc = update_configuration(build_descriptions(device, link_states), session, dryrun=dryrun)

        if rc is None:
            failed_devices.append(device)

        session.close()
    return {"succesful_devices": list(set(devices)-set(failed_devices)), "failed_devices": failed_devices}

def cli():
    # provide CLI functionality, isolated from modular functionality
    args = parse_args()

    if args.unique_credentials:
        output = set_description_based_on_lldp(args.devices, 
                                                 uc=True, 
                                                 dryrun=args.dryrun,
                                                 output=True)
    else:
        output = set_description_based_on_lldp(args.devices,
                                                 user=args.username,
                                                 password=args.password,
                                                 dryrun=args.dryrun,
                                                 output=True)
    if output["failed_devices"]:
        red('Failures'.center(80, '*'))
        [print(failure) for failure in output["failed_devices"]]

output_mode = False
if __name__ == "__main__":
    cli()
