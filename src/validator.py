import objects
import time
import asyncio
from copy import copy

# coroutine that will start another coroutine after a delay in seconds
async def delay(coro, seconds):
    # suspend for a time limit in seconds
    await asyncio.sleep(seconds)
    # execute the other coroutine
    print('Timeout triggered')
    coro()

class Validator:

    def __init__(self):
        self.pending_objects = {}

    #whenever thread receives block with unkown transactions invoke fetch, and call this
    def verification_pending(self, obj, queue, unknown_objects):
        print(f'New verification pending for object {obj}')
        self.pending_objects[objects.get_objid(obj)] = {
            'object' : obj,
            'queues' : [queue],
            'unknown_objects' : copy(unknown_objects), # don't pass by reference
            'unreceived_objects': copy(unknown_objects), # don't pass by reference
            'timeout' : time.time() + 5
        }
        asyncio.create_task(delay(self.timeout, 5))

    def timeout(self):
        for key in self.pending_objects.copy().keys():
            o = self.pending_objects[key]
            if o['timeout'] < time.time() and len(o['unreceived_objects']) > 0:
                #invalidate this
                for q in o['queues']:
                    q.put_nowait({
                        'type' : 'error',
                        'name' : 'UNFINDABLE_OBJECT',
                        'msg' : f'Timeout triggered for object {key}, did not receive {o["unreceived_objects"]}'
                    })
                self.pending_objects.pop(key)
                self.new_invalid_object(key)

    def is_pending(self, objectid):
        return objectid in self.pending_objects

    def add_peer(self, objectid, queue):
        if not self.is_pending(objectid):
            return
        o = self.pending_objects[objectid]
        if queue in o['queues']:
            return
        o['queues'].append(queue)

    # whenever new object recceived handle_connection calls this
    def received_object(self, objid):
        for key in self.pending_objects.copy().keys():
            o = self.pending_objects[key]
            unreceived_objects = o['unreceived_objects']
            if objid in unreceived_objects:
                unreceived_objects.remove(objid)

    #whenever a thread validated a new object
    def new_valid_object(self, objid):
        for key in self.pending_objects.copy().keys():
            o = self.pending_objects[key]
            unknown_objects = o['unknown_objects']
            if objid in unknown_objects:
                unknown_objects.remove(objid)
                if len(unknown_objects) == 0:
                    self.pending_objects.pop(key)
                    #send this into the thread queue
                    try:
                        for q in o['queues']:
                            q.put_nowait({
                                'type' : 'resumeValidation', #this is a special type to tell the thread to restart validation
                                'object': o['object'],
                            })
                    except Exception:
                        pass

    def new_invalid_object(self, objid):
        for key in self.pending_objects.copy().keys():
            o = self.pending_objects[key]
            unknown_objects = o['unknown_objects']
            if objid in unknown_objects:
                #this object is invalid
                #send this into the thread queue
                try:
                    for q in o['queues']:
                        q.put_nowait({
                            'msg': f"Object {key} depends on invalid object {objid}",
                            'name': "INVALID_ANCESTRY"
                        })
                    self.pending_objects.pop(key)
                    self.new_invalid_object(key)
                except Exception:
                    pass


