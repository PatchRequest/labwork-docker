def handle_histogram(assignment):
    assignment_string = assignment["text"]
    histogram = {}
    for char in assignment_string:
        if char in histogram:
            histogram[char] += 1
        else:
            histogram[char] = 1
    return histogram

def handle_caesar_cipher(assignment):
    action = assignment["action"]
    if action == "encrypt":
        return caesar_encrypt(assignment["plaintext"], assignment["letter_shift"])
    elif action == "decrypt":
        return caesar_decrypt(assignment["ciphertext"], assignment["letter_shift"])
    



def caesar_encrypt(text, shift):
    return caesar_shift(text, shift)

def caesar_decrypt(text, shift):
    return caesar_shift(text, -shift)

def caesar_shift(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            result += caesar_shift_char(char, shift)
        else:
            result += char
    return result

def caesar_shift_char(char, shift):
    if char.isupper():
        return chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
    else:
        return chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
