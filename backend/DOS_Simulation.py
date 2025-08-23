import time
import random
import threading
from tkinter import *
from tkinter import ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

# --- Setup window ---
window = Tk()
window.title("Safe DoS Simulation - VulnSight")

# Status Label
status_label = Label(window, text="Configure parameters and click Start", font=("Arial", 12))
status_label.pack(pady=10)

# Sliders for simulation
rps_label = Label(window, text="Requests per second")
rps_label.pack()
rps_slider = Scale(window, from_=1, to=1000, orient=HORIZONTAL)
rps_slider.set(50)
rps_slider.pack()

duration_label = Label(window, text="Duration (seconds)")
duration_label.pack()
duration_slider = Scale(window, from_=1, to=60, orient=HORIZONTAL)
duration_slider.set(10)
duration_slider.pack()

# Progress bar
progress = ttk.Progressbar(window, length=400, mode='determinate')
progress.pack(pady=10)

# Graph setup
fig, ax = plt.subplots(figsize=(5,2))
ax.set_xlim(0, 10)
ax.set_ylim(0, 120)
ax.set_xlabel("Time (s)")
ax.set_ylabel("Requests/sec")
line, = ax.plot([], [], color='red')
canvas = FigureCanvasTkAgg(fig, master=window)
canvas.get_tk_widget().pack()

# Simulation function
def simulate_dos():
    total_duration = duration_slider.get()
    target_rps = rps_slider.get()
    progress['value'] = 0
    progress['maximum'] = total_duration
    window.update_idletasks()

    times = []
    rps_values = []

    for t in range(1, total_duration+1):
        # Simulate requests sent
        simulated_rps = random.randint(int(target_rps*0.8), int(target_rps*1.2))
        times.append(t)
        rps_values.append(simulated_rps)

        # Update graph
        line.set_data(times, rps_values)
        ax.set_xlim(0, max(times)+1)
        ax.set_ylim(0, max(rps_values)+20)
        canvas.draw()

        # Update progress
        progress['value'] = t
        status_label.config(text=f"Simulating {simulated_rps} requests/sec at t={t}s")
        window.update_idletasks()
        time.sleep(1)

    # Determine severity
    avg_rps = sum(rps_values)/len(rps_values)
    if avg_rps > 800:
        severity = "HIGH"
    elif avg_rps > 400:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    status_label.config(text=f"Simulation complete! Estimated impact: {severity}")

# Start button
start_button = Button(window, text="Start Simulation", command=lambda: threading.Thread(target=simulate_dos).start())
start_button.pack(pady=10)

window.mainloop()
