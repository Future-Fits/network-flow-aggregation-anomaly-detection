import time
import numpy as np
from sklearn.preprocessing import StandardScaler
from keras.losses import MeanSquaredError
from keras.models import Sequential
from keras.layers import Dense
from bcc import BPF
import config as cfg

# Create BPF objects
bpf = BPF(src_file="port_flow.c")
packet_parser_func = bpf.load_func("packet_parser", BPF.SOCKET_FILTER)
BPF.attach_raw_socket(packet_parser_func, "")

class PortFlowAutoencoder:
    def __init__(self, input_dim, encoding_dim):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim

        # Initialize autoencoder model
        self.autoencoder = self.initialize_autoencoder()

        # Initialize dictionaries for training data and scalers
        self.train_map = {}
        self.scalers = {}

        # Initialize mean squared error object
        self.mean_squared_error = MeanSquaredError(reduction="none")

        # Initialize threshold
        self.threshold = 0

    def initialize_autoencoder(self):
        model = Sequential([
            Dense(self.encoding_dim, input_shape=(self.input_dim,), activation='relu'),
            Dense(self.input_dim)
        ])
        model.compile(optimizer='adam', loss='mean_squared_error')
        return model

    def train_autoencoder(self, data):
        # Clear to compute new scalers
        self.scalers = {}
        x_train_combined = []

        for port, data_list in data.items():
            # Standardize the dataset using a scaler for each port
            if port not in self.scalers:
                self.scalers[port] = StandardScaler()
            x_train_combined.extend(self.scalers[port].fit_transform(np.array(data_list)))

        x_train_combined = np.array(x_train_combined)

        # Train the autoencoder
        self.autoencoder.fit(x_train_combined, x_train_combined,
                             epochs=200, batch_size=8, shuffle=True, validation_split=0.1)

        # Compute threshold to detect anomalies
        x_pred = self.autoencoder.predict(x_train_combined)
        mse = self.mean_squared_error(x_train_combined, x_pred).numpy()
        #print("MSE during training:", mse) 
        self.threshold = np.percentile(mse, 95)
        print("Threshold: ", self.threshold)
        # Clear training dataset for the next period
        self.train_map = {}

    def predict_anomalies(self, port_num, data_point):
        # Check if key exists in the scalers, if not, create a new scaler
        if port_num not in self.scalers:
            print(f'Port {port_num} had not been utilized in the previous training period.')
            return True

        # Standardize the incoming data using the scaler for the current key
        x_scaled = self.scalers[port_num].transform([data_point])

        # Predict anomalies using reconstruction error for the current key
        x_pred = self.autoencoder.predict(x_scaled)
        mse = self.mean_squared_error(x_scaled, x_pred).numpy()
        print("Error: ", mse)
        # Identify anomalies and print for the current key
        if mse[0] > self.threshold:
            return True

# Initialize dataset and autoencoder

port_flow_autoencoder = PortFlowAutoencoder(cfg.input_dim, cfg.encoding_dim)

# Main loop similar to the first script
dataset_available = False
try:
    current_time = time.time()
    next_training_time = current_time + cfg.training_period
    while True:
        print("< -------- new period-------- >")

        # Iterate over flow data periodically
        for key, flow_stats in bpf.get_table("flow_data").items():
            print("Port: {}, Total Bytes Sent: {}, Total Packets: {}, "
                  "Avg Payload Size: {}, Max Payload Size: {}, Min Payload Size: {}"
                  .format(key.value, flow_stats.total_bytes_sent, flow_stats.total_packets,
                          flow_stats.avg_payload_size, flow_stats.max_payload_size,
                          flow_stats.min_payload_size))

            # Prepare data for autoencoder
            flow_data =  np.array([flow_stats.total_bytes_sent, flow_stats.total_packets,
                                      flow_stats.avg_payload_size, flow_stats.max_payload_size,
                                      flow_stats.min_payload_size], dtype=float)

            # Check if key exists in the training dataset, if not, create an empty list
            if key.value not in port_flow_autoencoder.train_map:
                port_flow_autoencoder.train_map[key.value] = []

            # Append the data for this period to the key's list
            port_flow_autoencoder.train_map[key.value].append(flow_data)

            # Predict anomalies only when it's time for predictions
            if current_time >= next_training_time - cfg.training_period and dataset_available:
                is_anomaly = port_flow_autoencoder.predict_anomalies(key.value, flow_data)
                if(is_anomaly):
                	print(f"Anomaly for Port {key.value}: {flow_data}")
                	
        # Train the autoencoder every 'training_period' seconds
        if current_time >= next_training_time:
            dataset_available = True
            print(f"Training model at {current_time}")
            if len(port_flow_autoencoder.train_map) > 0:
                # Train the model with the available data
                port_flow_autoencoder.train_autoencoder(port_flow_autoencoder.train_map)

            # Update the next training time
            next_training_time = current_time + cfg.training_period

        # Sleep until the next iteration or next training time
        #sleep_time = next_training_time - current_time if current_time < next_training_time else prediction_period
        current_time = time.time()
        time.sleep(cfg.prediction_period)

except KeyboardInterrupt:
    pass

