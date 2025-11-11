import cv2
import glob
import json
import networkx as nx
import matplotlib as mpl
import matplotlib.colors as mcolors
import matplotlib.pyplot as plt
import os
import textwrap
from tqdm import tqdm


mpl.use('QtAgg')


colors = {
    'green': '#8ECFC9',
    'orange': '#FFBE7A',
    'red': '#FA7F6F',
    'blue': '#82B0D2',
    'purple': '#BEB8DC',
    'beige': '#E7DAD2',
    'gray': '#999999',
    'lightgray': '#E9E9E9',
}


def plot_frame(graph, values, config_file, save_as):
    # Load the config file
    with open(config_file, 'r') as fr:
        json_object = json.load(fr)
        json_node = json_object['Node']
        json_edge = json_object['Edge']
    
    # Slightly smaller figure with extra right margin so the
    # overlay panel (node details) fits without clipping.
    fig, ax = plt.subplots(1, 1, figsize=(11, 5.5))
    plt.subplots_adjust(left=0.08, right=0.72)
    plt.title(f"{values['now']}")

    node_data = nx.get_node_attributes(graph, 'data')
    labels = {k: v.node_id for k, v in node_data.items()}
    if json_node['Basic']['colorWeight'] == 'on':
        # Use numeric values directly and map with a continuous colormap in [0,1]
        node_color = list(values['node'].values())
        node_cmap_colors = [
            (0, colors['purple']),
            (0.25, colors['blue']),
            (0.5, colors['green']),
            (0.75, colors['orange']),
            (1, colors['red']),
        ]
        node_cmap = mcolors.LinearSegmentedColormap.from_list('custom_cmap', node_cmap_colors)
    else:
        node_color = json_node['Basic']['color']
        node_cmap = None

    if json_edge['Basic']['colorWeight'] == 'on':
        edge_color = [v for k, v in values['edge'].items()]
        # edge_cmap = plt.cm.get_cmap(json_edge['ColorWeight']['cmap'])
        edge_cmap_colors = [(0, colors['purple']), (0.25, colors['blue']), (0.5, colors['green']), 
                            (0.75, colors['orange']), (1, colors['red'])]
        edge_cmap = mcolors.LinearSegmentedColormap.from_list('custom_cmap', edge_cmap_colors)
    else:
        edge_color = json_edge['Basic']['color']
        edge_cmap = None

    pos = nx.get_node_attributes(graph, 'pos')
    if not pos:
        pos = nx.spring_layout(graph, seed=0)

    coll = nx.draw_networkx_nodes(
        graph,
        pos=pos,
        node_size=json_node['Basic']['size'],
        node_color=node_color,
        cmap=node_cmap,
        vmin=0,
        vmax=1,
        node_shape=json_node['Basic']['shape'],
        linewidths=json_node['Basic']['linewidths'],
        alpha=json_node['Basic']['alpha'],
    )
    
    if json_node['Basic']['label'] == 'on':
        nx.draw_networkx_labels(
            graph,
            pos=pos,
            labels=labels,
            font_size=json_node['Label']['fontSize'],
            font_color=json_node['Label']['fontColor'],
        )
    
    nx.draw_networkx_edges(
        graph,
        pos=pos,
        arrows=json_edge['Basic']['arrows']=='true',
        edge_color=edge_color,
        edge_cmap=edge_cmap,
        style=json_edge['Basic']['style'],
        width=json_edge['Basic']['width'],
        alpha=json_edge['Basic']['alpha'],
    )

    if json_edge['Basic']['label'] == 'on':
        nx.draw_networkx_edge_labels(
            graph,
            pos=pos,
        )
    
    # Colorbar
    node_sm = plt.cm.ScalarMappable(cmap=node_cmap, norm=plt.Normalize(vmin=0, vmax=1))
    node_cb = plt.colorbar(node_sm, 
                           location='left', 
                           orientation='vertical', 
                           pad=0.01,
                           format=lambda x, _: f"{x:.0%}")
    node_cb.set_label("node", fontsize=10, labelpad=-5)
    edge_sm = plt.cm.ScalarMappable(cmap=edge_cmap, norm=plt.Normalize(vmin=0, vmax=1))
    edge_cb = plt.colorbar(edge_sm, 
                           location='right', 
                           orientation='vertical', 
                           pad=0.01,
                           format=lambda x, _: f"{x:.0%}")
    edge_cb.set_label("Link", fontsize=10, labelpad=-5)

    # Right-side overlay: wrap long lines instead of truncating with '...'
    props = dict(boxstyle='round', facecolor='grey', alpha=0.15)  # bbox features
    if 'target' in values and values['target']:
        info_blocks = []
        for k, v in values['target'].items():
            text = f"{k}: {v[0]} <-- {v[1]}"
            wrapped = textwrap.fill(text, width=40, break_long_words=False, break_on_hyphens=False)
            info_blocks.append(wrapped)
        info = "\n".join(info_blocks)
        # Place the overlay in figure coordinates so it never gets
        # cropped by the axes. The colorbar sits between axes and this box.
        fig.text(0.76, 0.5,
                 info,
                 fontsize=9,
                 va='center', ha='left',
                 bbox=props)
    plt.tight_layout()

    # # Change the color of node boundary
    # ax= plt.gca()
    # ax.collections[0].set_edgecolor("#000000")
    # plt.axis('off')

    plt.savefig(save_as)
    # plt.show()
    plt.close()


def frame2video(img_path, video_save_as):
    img_array = []
    files = glob.glob(f"{img_path}/*.png")
    files.sort(key=os.path.getmtime)  # sort all images in time order.
    for filename in tqdm(files):
        img = cv2.imread(filename)
        height, width, layers = img.shape
        size = (width, height)
        img_array.append(img)
    
    out = cv2.VideoWriter(video_save_as, 
                          cv2.VideoWriter_fourcc(*'DIVX'), 
                          fps=5, 
                          frameSize=size)
    
    for i in range(len(img_array)):
        out.write(img_array[i])
    
    out.release()


def vis_frame2video(env):
    """Build the simulation video, based on the simulation logs.

    Resolves the visualization config relative to this module so it works
    no matter where the script is launched from.
    """
    frame_save_path = f"{env.config['VisFrame']['LogFramesPath']}"
    if len(os.listdir(frame_save_path)) == 0:
        with open(f"{env.config['VisFrame']['LogInfoPath']}/frame_info.json", 'r') as fr:
            info4frame = json.load(fr)

        # Resolve config path relative to this file instead of CWD
        here = os.path.dirname(os.path.abspath(__file__))
        cfg_path = os.path.join(here, 'configs', 'vis_config_4video.json')

        for k, v in tqdm(info4frame.items()):
            v['now'] = k
            plot_frame(env.scenario.infrastructure.graph,
                       v,
                       config_file=cfg_path,
                       save_as=f"{frame_save_path}/frame_{k}.png")

    frame2video(frame_save_path, f"{env.config['VisFrame']['LogInfoPath']}/out.avi")
