import networkx as nx
import pdb

G = nx.DiGraph()

G.add_node('1')
G.add_node('2')
G.add_node('3')
G.add_edge('1','2')
G.add_edge('1','3')
cG = nx.simple_cycles(G)

for g in cG:
    pdb.set_trace()
    x=2

pdb.set_trace()
x=3

