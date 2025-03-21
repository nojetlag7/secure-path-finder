from flask import Flask, request, jsonify
from flask_cors import CORS #enables frontend apps to communicate with the backend
import numpy as np #for performing matrix operations in encryption
import networkx as nx #llbrary for graph based pathfinding

app = Flask(__name__)
CORS(app)  # Enable CORS for local development



# Locations with coordinates (latitude, longitude)
locations = {
    "Accra": {"coords": [5.6037, -0.1870]},
    "Tema": {"coords": [5.6690, -0.0166]},
    "Kumasi": {"coords": [6.6885, -1.6244]},
    "Cape Coast": {"coords": [5.1053, -1.2466]},
    "Takoradi": {"coords": [4.8932, -1.7554]},
    "Ho": {"coords": [6.6008, 0.4713]},
    "Tamale": {"coords": [9.4075, -0.8530]},
    "Koforidua": {"coords": [6.0941, -0.2591]},
    "Bolgatanga": {"coords": [10.7873, -0.8514]}
}


# Graph edges with weights (represent distance)
edges = [
    ("Accra", "Tema", 25),
    ("Accra", "Kumasi", 250),
    ("Accra", "Cape Coast", 145),
    ("Tema", "Ho", 150),
    ("Kumasi", "Takoradi", 210),
    ("Kumasi", "Tamale", 380),
    ("Cape Coast", "Takoradi", 130),
    ("Ho", "Koforidua", 80),
    ("Tamale", "Bolgatanga", 161),
    ("Koforidua", "Accra", 87)
]


# Create an undirected graph and add nodes and edges
G = nx.Graph()
for node, data in locations.items():
    G.add_node(node, coords=data["coords"])
for u, v, weight in edges:
    G.add_edge(u, v, weight=weight)

# --- Hill Cipher Functions (2x2 Key) ---

# Our chosen 2x2 key matrix (must be invertible mod 26)
key_matrix = np.array([[8, 3],
                       [2, 5]])

def hill_encrypt(text, key_matrix):
    """
    Encrypt text using a Hill cipher with a given key_matrix.
    This function:
    - Converts text to uppercase, strips spaces.
    - Pads the text to a length multiple of the key dimension.
    - Encrypts block by block (here, blocks of 2 characters).
    """
    text = text.upper().replace(" ", "") #changing the path into uppercase and removing whitespaces
    n = key_matrix.shape[0]
    # Pad with 'X' if necessary.
    if len(text) % n != 0:
        text += 'X' * (n - len(text) % n)
    encrypted_text = ""
    for i in range(0, len(text), n):
        block = text[i:i+n]
        block_vector = np.array([ord(c) - ord('A') for c in block])
        encrypted_vector = np.dot(key_matrix, block_vector) % 26
        encrypted_block = ''.join(chr(int(num) + ord('A')) for num in encrypted_vector)
        encrypted_text += encrypted_block
    return encrypted_text

def mod_matrix_inv(matrix, modulus):
    """
    Computes the modular inverse of a 2x2 matrix under the given modulus.
    """
    if matrix.shape != (2,2):
        raise NotImplementedError("Modular inverse only implemented for 2x2 matrices.")
    a, b, c, d = matrix.flatten()
    det = a*d - b*c
    # Find multiplicative inverse of det modulo modulus
    try:
        det_inv = pow(det, -1, modulus)
    except ValueError:
        raise ValueError("The key matrix is not invertible modulo {}".format(modulus))
    inv_matrix = np.array([[d, -b],
                           [-c, a]])
    inv_matrix = (det_inv * inv_matrix) % modulus
    return inv_matrix

def hill_decrypt(ciphertext, key_matrix):
    """
    Decrypt text using a Hill cipher with the given key_matrix.
    """
    n = key_matrix.shape[0]
    inv_key_matrix = mod_matrix_inv(key_matrix, 26)
    decrypted_text = ""
    for i in range(0, len(ciphertext), n):
        block = ciphertext[i:i+n]
        block_vector = np.array([ord(c) - ord('A') for c in block])
        decrypted_vector = np.dot(inv_key_matrix, block_vector) % 26
        decrypted_block = ''.join(chr(int(num) + ord('A')) for num in decrypted_vector)
        decrypted_text += decrypted_block
    return decrypted_text

# --- API Endpoint ---

@app.route('/shortest-path', methods=['POST'])
def get_shortest_path():
    data = request.json
    start = data.get('start')
    end = data.get('end')

    # Validate inputs
    if start not in G.nodes or end not in G.nodes:
        return jsonify({"error": "Start or end node not found."}), 400

    try:
        # Compute shortest path based on edge weights
        path = nx.shortest_path(G, source=start, target=end, weight='weight')
    except nx.NetworkXNoPath:
        return jsonify({"error": "No path exists between {} and {}.".format(start, end)}), 400

    # For each node in the path, encrypt its name (pad to length 2 if needed)
    encrypted_path = [hill_encrypt(node, key_matrix) for node in path]
    
    # Collect coordinates for mapping (in order of the path)
    route_coords = [G.nodes[node]['coords'] for node in path]

    response = {
        "plain_path": path,
        "encrypted_path": encrypted_path,
        "route_coords": route_coords
    }
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
