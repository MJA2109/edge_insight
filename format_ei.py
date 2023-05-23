from rich.console import Console
from rich.table import Table
from rich.tree import Tree

def format_fw_output(data_input):

    table = Table(title="FW CONNECTION STATS", title_style="black on yellow", show_header=False)

    for item in data_input:
        for key in item:
            table.add_row(key, item[key])
        table.add_section()
    console = Console()
    console.print(table)


def format_output(data_input, name):

    table = Table(title=name, title_style="black on yellow", show_header=False)

    for key in data_input:
        table.add_row(key, str(data_input[key]))    
    console = Console()
    console.print(table)


