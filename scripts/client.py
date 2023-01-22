import snap7

address = '127.0.0.1'
db_number = 1
rack = 1
slot = 1
tcpport = 102


def db_get(client):
    return client.db_get(db_number)


def db_read(client):
    buffer = client.db_read(db_number = db_number, start = 0, size = 50)
    return buffer


def db_write(client):
    client.db_write(db_number = db_number, start = 0, data = bytearray(b'Hello from MEPhI!'))


def get_block_info(client):
    return client.get_block_info('DB', db_number)


def get_cp_info(client):
    return client.get_cp_info()


def get_cpu_info(client):
    return client.get_cpu_info()


def get_exec_time(client):
    return client.get_exec_time()


def list_blocks(client):
    return client.list_blocks()


client_wrap = {
    'db_get': db_get,
    'db_read': db_read,
    'db_write': db_write,
    'get_block_info': get_block_info,
    'get_cp_info': get_cp_info,
    'get_cpu_info': get_cpu_info,
    'get_exec_time': get_exec_time,
    'list_blocks': list_blocks
}


if __name__ == '__main__':
    client = snap7.client.Client()
    client.connect(address, rack, slot, tcpport)
    
    while True:
        request_type = input('Request: ')
        if request_type in [*client_wrap]:
            response = client_wrap[request_type](client)
            print('Response:', response or 'blank')
        elif request_type == 'plc_stop':
            break
        else:
            print('Request type is invalid!')
    
    client.disconnect()
    client.plc_stop()