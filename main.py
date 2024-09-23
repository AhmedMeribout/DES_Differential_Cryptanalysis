from DesFunctions import *
 




pt="B0E0AECE5175194C"

ct="E1EC5D57AF996C74" 




diffct = [
 "A3E95D13AF986475",
 "E0F85951BF196C60",
 "E0AC5D56F7DD6E75",
 "E1E45DC6EE996860",
 "E1EC5557A7DD6C75",
 "E16C4D47AFD92D3D",
 "E8AC7956EF897D74",
 "E1EC5C57AEB92854",
 "70AC5C47BF992A74",
 "F1EC1CC7AEB96860",
 "E0F95913BD99EC74",
 "E1FE1C37AF986D34",
 "E0EC5B57BD996C74",
 "E08C5D57AB8D6D36",
 "E3E95512EF8C6C74",
 "A1EC4D57AF916D3C",
 "C1E94D57ABD9FC34",
 "A1EC1C77AFD16D34",
 "F5EC5C572E990C60",
 "E16C5D4FAFCD2C75",
 "E1ECDD572F992860",
 "E1E05D52EF986CF0",
 "71EC5E03AF992874",
 "E0EC5D57BF8F6C76",
 "FCAC5856EF894C74",
 "E0EC595FAFCF6C75",
 "A5EC5C578B997575",
 "E0DC5951BB996D34",
 "E5EC7C578B996C74",
 "F5FE1C17AE982854",
 "C1ECCD47AAD93834",
 "E1ED5D53AF186CF4"
]

possible_keys = [[] for _ in range(8)] 



def findPossibleKeys(bits, Edr_array, Er_array, A_array):
    possible_keys = [[] for _ in range(8)]
    
    for j in range(8):
        for sk in bits: 
            B = xorthensbox(Edr_array[j], sk, j)
            C = xorthensbox(Er_array[j], sk, j)
            x = xor(B, C)
            if A_array[j] == x:
                possible_keys[j].append(sk)
    
    return possible_keys


def getLandD(ct, initial_perm):
    # Convert hexadecimal ciphertext to binary
    ct_binary = hex2bin(ct)
    
    # Apply initial permutation
    ct_permuted = permute(ct_binary, initial_perm, 64)
    
    # Split permuted text into L16 and R16
    l16 = ct_permuted[:32]
    r16 = ct_permuted[32:64]
    
    return l16, r16


def filter_possible_keys(diffct, l16, r16, initial_perm, inverse_per, exp_d, possible_keys):
    for i in diffct:
        # Redo the initial steps with the new ciphertext
        dct = i

        dl, dr = getLandD(dct, initial_perm)
        xor_l_dl = xor(l16, dl)
        A = permute(xor_l_dl, inverse_per, 32)
        A_array = split_binary_into_segments(A, 4)
        Er = permute(r16, exp_d, 48)
        Edr = permute(dr, exp_d, 48)
        Er_array = split_binary_into_segments(Er)
        Edr_array = split_binary_into_segments(Edr)
        
        # Iterate over the possible keys and remove the ones that don't match
        for j in range(0, 8):
            for s in possible_keys[j]:
                B = xorthensbox(Edr_array[j], s, j)
                C = xorthensbox(Er_array[j], s, j)
                x = xor(B, C)
                if A_array[j] != x:
                    possible_keys[j].remove(s)


def find_key(pt, ct, permuted_key):
    all_combinations = generate_combinations(permuted_key)
    final_key = ""
    for combination in all_combinations:
        key = ''.join(combination)
        cipher = DES(pt, key)
        if cipher == ct:
            final_key = key
            break
    return final_key


if __name__ == "__main__":
    #Cyphertex without the fault
    l16, r16 = getLandD(ct, initial_perm)

    #Cyphertext with the fault
    dct = diffct[0]
    dl16, dr16 = getLandD(dct, initial_perm)

    #XOR of the left part of the cyphertext and the left part of the cyphertext with the fault
    xor_l_dl = xor(l16,dl16)
    

    # Permute the XOR result of left and right halves with the inverse permutation P^-1
    A = permute(xor_l_dl, inverse_per, 32)

   

    # Permute the right half with the expansion permutation to get a 48-bit result
    Er = permute(r16, exp_d, 48)

    # Permute the faulty right half with the expansion permutation to get a 48-bit result
    Edr = permute(dr16, exp_d, 48)

    # Split the result of permutation A into segments of 4 bits
    A_array = split_binary_into_segments(A, 4)

    # Split the result of permutation Er into segments of 6 bits
    Er_array = split_binary_into_segments(Er)

    # Split the result of permutation Edr into segments of 6 bits
    Edr_array = split_binary_into_segments(Edr)


     # Generate all possible combinations of 6 bits
    bits = generate_bit_combinations(6)

    possible_keys = findPossibleKeys(bits, Edr_array, Er_array, A_array)


    #Print the number of possible solutions for each equation
    for i,line in enumerate(possible_keys):
        print("equation ",i+1, " : ", len(line)," solutions")



    #Iterate over the different cyphertexts with faults
    filter_possible_keys(diffct, l16, r16, initial_perm, inverse_per, exp_d, possible_keys)



    #Print the number of possible solutions for each equation after the filtering
    for i,line in enumerate(possible_keys):
        print("equation ",i+1, " : ", len(line), "solution after filtering")
    # Join the inner arrays into strings
    inner_strings = [''.join(inner) for inner in possible_keys]

# Join the inner strings into a final string
    k16 = ''.join(inner_strings)

# Print the result
    print("k16: ", k16, " (", len(k16), " bits)")
    print("k16: ", bin2hex(k16), " (", len(bin2hex(k16)), " hex)")


    permuted_key = permuteArray(k16,inverse_pc2,56)

    #Brute force the last 9 bits of the key 
    final_key = find_key(pt, ct, permuted_key)


    print("K' : " , final_key)
    print("K' : " , bin2hex(final_key))

    final_key = permuteArray(final_key,inverse_pc1,64)
    final_key = ''.join(final_key)

    print("Key Without parity bits: " , bin2hex(final_key))


    final_key = add_parity_bits(final_key)
    print("Key With parity bits : " , final_key)
    print("Key With parity bits : " , bin2hex(final_key))



    #Test of the result :

    # getting 56 bit key from 64 bit using the parity bits
    key = permute(final_key, pc1, 56)
    #Encryption
    cypher = DES(pt,key)
    #Printing the result
    print("Cypher : " , cypher)
    print("Cypher test : " , ct)

    if cypher == ct:
        print("The key is correct")


