#!/usr/bin/env python
#
# Copyright 2022 Carter Yagemann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from graph_tool.draw import graphviz_draw

def save_graph(graph, units, ofp):
    """Save graph to a file.

    Keyword Arguments:
    graph -- The graph to save.
    units -- Execution units (used for coloring and filtering).
    ofp -- Output filepath.
    """
    # create vertex properties
    vprops={"label": graph.vp.node,
            "shape": "box"}

    # create vertex colors
    vcolor = graph.new_vertex_property("string", val="#ffffff")
    # mark all unit heads and release points
    for unit in units:
        vcolor[graph.gp.node2idx[unit['head']]] = "#bdbcf4"
        for caller in unit['safe_callers']:
            vcolor[graph.gp.node2idx[caller]] = "#ecd1a0"

    # filter out any objects that don't contain units to keep
    # the graph concise
    objs_with_units = set()
    for unit in units:
        objs_with_units.add(unit['object'])

    filter = graph.new_vertex_property("bool", val=0)

    for v in graph.vertices():
        if graph.vp.node[v].obj['name'] in objs_with_units:
            filter[v] = 1

    # apply filter mask
    graph.set_vertex_filter(filter)

    graphviz_draw(graph, overlap=False, vprops=vprops,
            vcolor=vcolor, output=ofp)

    # clear filter mask
    graph.clear_filters()
