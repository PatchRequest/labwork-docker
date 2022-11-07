import base64
from helper import split_into_blocks


def handle_chi_square(assignment):
    
    action = assignment["action"]
    if action == "decimate":
        return do_decimate(assignment)
    elif action == "histogram":
        return do_histogram(assignment)
    elif action == "chi_square":
        return do_chi_square(assignment)
    

def do_decimate(assignment):
    return_values = []
    data = base64.b64decode(assignment["data"])
    selectors = assignment["selectors"]

    for selector in selectors:


        offset = int(selector.get("offset", 0))
        stride = int(selector.get("stride", 1))
        

        return_values.append({"decimated_data": base64.b64encode(data[offset::stride]).decode("utf-8")})
    return return_values


    pass
def do_histogram(assignment):
    return_values = []
    data = do_decimate(assignment)

    for set in data:
        histogram = {}
        bytes = base64.b64decode(set['decimated_data'])
        for byte in bytes:
            # byte as int
            if byte in histogram:
                histogram[byte] += 1
            else:
                histogram[byte] = 1

        return_values.append({"histogram": histogram})

    return return_values


def do_chi_square(assignment):
    return_values = []
    histograms = do_histogram(assignment)
    for histogram in histograms:
        
        # n = number of bytes
        n = sum(histogram['histogram'].values())
        m = 256

        # fill histogram with 0 if not present
        for i in range(0, 256):
            if i not in histogram['histogram']:
                histogram['histogram'][i] = 0



        chi_square = 0
        for bin in histogram['histogram'].values():
            chi_square += (bin - n/m)**2 
        chi_square = chi_square*(m/n)
  
        upper_limit = 311
        lower_limit = 205

        our_date = {
            "chi_square_statistic": round(chi_square),
            "verdict": "no_result" if lower_limit <= chi_square <= upper_limit else "uniform" if chi_square < lower_limit else "non_uniform"
        }
  
        return_values.append(our_date)
    return return_values

