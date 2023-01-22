from snap7.server import logger, Server
from snap7 import types

import time

tcpport = 102


def mainloop(tcpport: int = 1102):
    server = Server()
    size = 100
    DBdata = (types.wordlen_to_ctypes[types.WordLen.Byte.value] * size)()
    PAdata = (types.wordlen_to_ctypes[types.WordLen.Byte.value] * size)()
    TMdata = (types.wordlen_to_ctypes[types.WordLen.Byte.value] * size)()
    CTdata = (types.wordlen_to_ctypes[types.WordLen.Byte.value] * size)()
    server.register_area(types.srvAreaDB, 1, DBdata)
    server.register_area(types.srvAreaPA, 1, PAdata)
    server.register_area(types.srvAreaTM, 1, TMdata)
    server.register_area(types.srvAreaCT, 1, CTdata)
    
    server.start(tcpport = tcpport)
    while True:
        while True:
            event = server.pick_event()
            if event:
                logger.info(server.event_text(event))
            else:
                break
        
        time.sleep(1)


if __name__ == '__main__':
    mainloop(tcpport)