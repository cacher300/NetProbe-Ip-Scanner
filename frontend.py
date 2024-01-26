import threading

def print_h():
    print("h")

# List to keep track of threads
threads = []

# Create 1000 threads
for _ in range(1000):
    thread = threading.Thread(target=print_h)
    threads.append(thread)

# Start all threads
for thread in threads:
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()
