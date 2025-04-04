from block_cipher import decrypt
from yao_circuit import GarbledGate as Ggate
import json

# garbled truth tables
G_Table = {
    5: [(6829921, 11451673), (1515696, 6333149), (15107502, 8186257), (5872557, 12241756)], 
    6: [(13415489, 4332242), (5144037, 9578022), (15201634, 13202380), (10357348, 15158424)], 
    7: [(1587462, 6581034), (8356378, 2216472), (11762280, 3875959), (5982650, 7776773)], 
    9: [(5728291, 11896856), (12052243, 1282564), (10228672, 10487067), (6137078, 8217550)]
    }

# Note that this keys table belongs to Alice.
# The values at index positions 0 and 1 of the tuple correspond to the labels for input bits 0 and 1, respectively.
# keys = {1: (15233817, 1315943), 
#         2: (15274501, 5158879), 
#         3: (7431802, 16682547), 
#         4: (11945610, 6753699), 
#         5: (13849459, 4637545), 
#         6: (10453495, 2479542), 
#         7: (2068375, 13039971), 
#         9: (7508273, 12723289)}

# Bob gets the wires
# alice_input = (keys[1][1],keys[2][0])
# bob_input = (keys[3][1],keys[4][1])
alice_input = (1315943 ,15274501)
bob_input = (16682547, 6753699)

# load circuit
circuit_filename = "circuit_map.json"
with open(circuit_filename) as json_file:
    circuit = json.load(json_file)

# evaluate the truth_table given the two input labels
def validate_the_circuit(geta_table, key0, key1):
    for g in geta_table:
        gl, v = g
        label = decrypt(gl, key0, key1)
        validation = decrypt(v, key0, key1)

        if validation == 0:
            return label
        
labels_dict = {}
user_input = {1: alice_input[0], 2: alice_input[1], 3: bob_input[0], 4: bob_input[1]}
gates = circuit["gates"]
wires = set()
for gate in gates:
    wires.add(gate["id"])
    wires.update(set(gate["in"]))
for wireidx in wires:
    # the index of keys[wireidx] 1 and 0 means TRUE and FALSE in garbled circuit
    if wireidx in user_input:
        labels_dict[wireidx] = user_input[wireidx]
    else:
        labels_dict[wireidx] = -1

while True:
    for gate in gates:
        out_id = gate["id"]
        input = gate["in"]
        
        if labels_dict[input[0]] == -1 or labels_dict[input[1]] == -1:
            continue
        else:
            garbled_table = G_Table[out_id]
            key0 = labels_dict[input[0]]
            key1 = labels_dict[input[1]]
            labels_dict[out_id] = validate_the_circuit(garbled_table, key0, key1)
    target = circuit["out"][0]
    if labels_dict[target] != -1:
        print("The target label is: ", labels_dict[target])
        break