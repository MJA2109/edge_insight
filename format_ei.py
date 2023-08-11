from rich.console import Console
from rich.table import Table
from rich.tree import Tree
import pprint
import re

def format_list_output(data_input, name):

    table = Table(title=name, title_style="black on yellow", show_header=False)

    for item in data_input:
        for key, value in item.items():
            table.add_row(key, str(value))
        table.add_section()
    console = Console()
    console.print(table)
    

def format_dict_output(data_input, name):

    table = Table(title=name, title_style="black on yellow", show_header=False)

    for key in data_input:
        table.add_row(key, str(data_input[key]))    
    console = Console()
    console.print(table)
    


