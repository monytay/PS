import hcl2



 # we parse the data into a python dictionary first with hcl2 library
def parse(filePlaceholder):
    with open(filePlaceholder, 'r') as f:
        data = hcl2.load(f)
    return data

def ScannerApp(filePath):
    # Parse the file using our method so we can run our checks
    data = parse(filePath)
    # Set our initial data count, and what CIS rule it broke
    vulnerabilityCount = 0
    cisRuleBroken = ""

    # Implement our 6 CIS AWS rule checks 
    