import itertools

def handle_password_keyspace(assignment):
    alphabet = assignment["alphabet"]
    length = assignment["length"]
    restrictions = assignment["restrictions"]
    combinations = []
    count = 0

    for i in itertools.product(alphabet, repeat=length):
        combinations.append(''.join(map(str, i)))

    for comb in combinations:
        valid= True
        for restriction in restrictions:
            if not test_restriction(restriction, comb):
                valid = False
        if valid:
            count += 1

    return {"count": count}

def test_restriction(rest, comb):
    special_chars = "!@#$%^&*()_+-="
    match rest:
        case 'at_least_one_special_char':
            return any(char in comb for char in special_chars)
        case 'at_least_one_uppercase_char':
            return any(char.isupper() for char in comb)
        case 'at_least_one_lowercase_char':
            return any(char.islower() for char in comb)
        case 'at_least_one_digit':
            return any(char.isdigit() for char in comb)
        case 'no_consecutive_same_char':
            return not any(char == comb[i+1] for i, char in enumerate(comb[:-1]))
        case 'special_char_not_last_place':
            return comb[-1] not in special_chars