
def scanning_animation(stop_event):
    chars = ['|', '/', '-', '\\']
    index = 0
    while not stop_event.is_set():
        print(f"\r\x1b[KScanning: {chars[index % len(chars)]}", end='', flush=True)
        index += 1
        stop_event.wait(0.1)