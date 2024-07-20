from ncclient import manager
from ncclient.transport.session import *
from threading import Thread, Lock
import time

class Listener(SessionListener):

    def __init__(self, pool, analyze_notification, analyze_rpc_reply):
        super().__init__()
        self.pool = pool
        self.analyze_notification = analyze_notification
        self.analyze_rpc_reply = analyze_rpc_reply
        self.stop = False

    def errback(self, ex):
        # print(ex)
        pass

    def stopListening(self):
        self.stop = True

    def callback(self, root, raw):
        tag, _ = root
        if self.stop:
            # print("Listener Stoped:", root)
            # print("Listener Stoped:", raw)
            return
        print(raw)
        if tag == qualify('notification', NETCONF_NOTIFICATION_NS):  # check if it is a Netconf notification
            # log_writeln("Notification -> " + raw + "\n")
            root = etree.fromstring(raw)
            self.pool.add_task(self.analyze_notification, root)
        else:  # RCP Notification
            rpc_reply = raw
            self.pool.add_task(self.analyze_rpc_reply, rpc_reply)

class Worker(Thread):
    # Thread executing tasks from a given tasks queue

    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args = self.tasks.get()
            try:
                func(args[0])
            except Exception as e:
                # An exception happened in this thread
                print(e)
            finally:
                # Mark this task as done, whether an exception happened or not
                self.tasks.task_done()

class ThreadPool:
    # Pool of threads consuming tasks from a queue

    def __init__(self, num_threads, workers):
        self.tasks = Queue()
        for _ in range(num_threads):
            workers.append(Worker(self.tasks))

    def add_task(self, func, *args):
        # Add a task to the queue
        self.tasks.put((func, args))

def analyze_notification(notification):
    print('ANALYZE NOTIFICATION')
    print(notification)
    sadb_notification = notification.find("{http://example.net/ietf-ipsec}sadb_expire")
    if sadb_notification is not None:
        state = notification.find("{http://example.net/ietf-ipsec}sadb_expire").find(
            "{http://example.net/ietf-ipsec}state").text
        print(state)


def analyze_rpc_reply(rpc_reply):
    print('ANALYZE NOTIFICATION')
    print(rpc_reply)


workers = []
pool = ThreadPool(50, workers)
listener = Listener(pool, analyze_notification, analyze_rpc_reply)


m = manager.connect(host="localhost", port=830, username="netconf", password="netconf",
                    hostkey_verify=False)
m._session.add_listener(listener)
m.create_subscription()

while True:
    time.sleep(1)
