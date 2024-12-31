import psutil
import time
from flask import Flask, render_template, Response
from flask_sse import sse
import json
from threading import Thread

app = Flask(__name__)
app.config["REDIS_URL"] = "redis://localhost"
app.config["SSE_REDIS_URL"] = "redis://localhost"
app.register_blueprint(sse, url_prefix='/stream')

class SystemMonitor:
    def __init__(self):
        self.previous_network = psutil.net_io_counters()
        self.previous_time = time.time()

    def get_system_stats(self):
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Get process information
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu': pinfo['cpu_percent'],
                    'memory': pinfo['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Calculate network speed
        current_network = psutil.net_io_counters()
        current_time = time.time()
        
        network_speed = {
            'upload': (current_network.bytes_sent - self.previous_network.bytes_sent) / (current_time - self.previous_time),
            'download': (current_network.bytes_recv - self.previous_network.bytes_recv) / (current_time - self.previous_time)
        }
        
        self.previous_network = current_network
        self.previous_time = current_time

        return {
            'cpu': cpu_percent,
            'memory': memory.percent,
            'disk': disk.percent,
            'network': network_speed,
            'processes': processes
        }

monitor = SystemMonitor()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/kill/<int:pid>', methods=['POST'])
def kill_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()  # Try to terminate gracefully first
        time.sleep(1)
        if process.is_running():
            process.kill()  # Force kill if still running
        return {'success': True, 'message': f'Process {pid} terminated'}
    except psutil.NoSuchProcess:
        return {'success': False, 'message': 'Process not found'}, 404
    except psutil.AccessDenied:
        return {'success': False, 'message': 'Permission denied'}, 403
    except Exception as e:
        return {'success': False, 'message': str(e)}, 500

def generate_stats():
    with app.app_context():
        while True:
            try:
                stats = monitor.get_system_stats()
                sse.publish(stats, type='stats')
                time.sleep(1)
            except Exception as e:
                print(f"Error in stats generation: {e}")
                time.sleep(5)  # Wait before retrying

if __name__ == '__main__':
    stats_thread = Thread(target=generate_stats)
    stats_thread.daemon = True
    stats_thread.start()
    
    # Run the Flask app
    app.run(debug=True, threaded=True, port=5000)
