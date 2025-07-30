from flask import Flask, render_template, request, jsonify
import sys, os, json, re, uuid, firebase_admin
from firebase_admin import credentials, db
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,pair
from charm.toolbox.hash_module import Hash
from hashlib import sha256
import base64, secrets, time
from Crypto.Cipher import AES
from datetime import datetime
import random
# from sympy import mod_inverse

n = 5 # Number of members
t_0 = 3 # Degrees of polynomials

eta = 5 # Number of distributed
t_1 = 3 # Degrees of polynomials

# Assuming that the bilinear group is initialised using the SS512 curve
group = PairingGroup('SS512')
hash_obj = Hash('sha256', group)

def H0(x):
  # Mapping an arbitrary length 01 string to a G1 group element
  return group.hash(x, G1)

def H1(sigma):
  # Mapping G1 group elements to ZR group elements
  return group.hash(group.serialize(sigma), ZR)

def H2(b0, b1):
  # Mapping (ZR group element * ZR group element) to ZR group element
  return group.hash(group.serialize(b0 * b1), ZR)

# def H3(x):
#   # Mapping arbitrary length 01 strings to ZR group elements
#   return H1(H0(x))

def H3(x):
  # Mapping arbitrary length 01 strings to ZR group elements
  x_bytes = x.encode('utf-8')
  return group.hash(x_bytes, ZR)

def H4(bilinear_pair):
  # Mapping GT group elements to ZR group elements
  return group.hash(group.serialize(bilinear_pair), ZR)

def H5(z, g):
  """
  H5: Zp × G → {0,1}*
  Maps elements from Zp and group G to a binary string of arbitrary length
  """
  # Serialise Zp and G group elements to byte streams respectively
  z_bytes = group.serialize(z)
  g_bytes = group.serialize(g)
  
  # Merging Byte Streams and Hashing with H Functions
  combined_bytes = z_bytes + g_bytes
  
  # Hash the merged byte stream to get a fixed length 256-bit binary string
  hash_result = sha256(combined_bytes).digest()  # Generates a fixed-length 256-bit binary string.
  
  # Convert to binary string
  binary_string = ''.join(format(byte, '08b') for byte in hash_result)
  
  # desired_length = random.randint(256, 512)  # Desired output length (e.g. 318 bits)
  desired_length = 256  # Fixed desired output length (e.g. 256 bits)
  print(f"Desired output length desired_length: {desired_length}")
  # If the length of the generated binary string is less than the required length, continue hashing until the length is reached
  while len(binary_string) < desired_length:
      hash_result = sha256(hash_result).digest()  # Continue to use hashes to generate more data
      binary_string += ''.join(format(byte, '08b') for byte in hash_result)
      
  # Intercept to desired length
  return binary_string[:desired_length]

def H6(x):
  # Mapping ********* to ZR group elements
  return group.hash(group.serialize(x), ZR)

def PRF(z, w):
  """
  PRF: Zp × {0,1}* → {0,1}*
  Maps elements from Zp and {0,1}* to a binary string of arbitrary length
  """
  # Serialise Zp and G group elements to byte streams respectively
  z_bytes = group.serialize(z)
  w_bytes = w.encode('utf-8')
  
  # Combine the byte streams and hash them using the h function
  combined_bytes = z_bytes + w_bytes
  
  # Hash the combined byte stream to get a fixed-length 256-bit binary string
  hash_result = sha256(combined_bytes).digest() # Generate a fixed-length 256-bit binary string
  
  # Convert to binary string
  binary_string = ''.join(format(byte, '08b') for byte in hash_result)
  # Here, to simplify the process, a fixed-length output is used.
  desired_length = random.randint(256, 512) # desired output length (e.g. 318 bits)
  desired_length = 389 # Fixed desired output length (e.g. 256 bits)
  # print(f "Desired output length desired_length: {desired_length}")
  # If the generated binary string is less than the desired length, continue hashing until it reaches length
  while len(binary_string) < desired_length:
    hash_result = sha256(hash_result).digest()  # Continue to use hashes to generate more data
    binary_string += ''.join(format(byte, '08b') for byte in hash_result)

  # intercept to desired length
  return binary_string[:desired_length]
  # # return binary_string
  # return hash_result # Returns the original 256-bit binary string
    


def measure_time(func):
  def wrapper(*args, **kwargs):
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    execution_time = (end_time - start_time) * 1000
    # return result, execution_time
    return execution_time
  return wrapper

# Generate 01 string
def generate_random_binary_string(length):
    return ''.join(random.choice('01') for _ in range(length))

# bilinear pair operation
def bilinear_pairing(g1, g2):
    return pair(g1, g2)

class PCSE:
  def __init__(self, group):
    self.group = group

    self.g = group.random(G1) # A generator of G 
    self.gamma = group.random(G1) # A generator of G 
    self.v = group.random(G1) # A generator of G 
    self.epsilon = group.random(G1) # A generator of G 
    self.h = group.random(G1) # A generator of G 
    
    self.r = self.group.random(ZR) # master secret keys
    self.d = self.group.random(ZR) # master secret keys
    self.s = self.group.random(ZR) # master secret keys
    self.a = self.group.random(ZR) # master secret keys
    
    self.omega1 = self.g ** (self.r / self.d)
    self.u = self.s / self.d
    self.omega2 = self.g ** (self.r * self.u)
    self.g1 = self.g ** self.a


  def f0_x(self, x):
    temp0 = 0
    temp0 = self.group.init(ZR, int(temp0))
    for j in range(1, t_0): # The original formula sums from 1 to t0-1, i.e., i from 0 to t0-2; in fact, it should be a randomly selectable a0 and a1 here, rather than the first t0-1 in order.
      j_zr = self.group.init(ZR, int(j))
      temp0 += self.a0[j - 1] * (x ** j_zr)
    f0_x = self.r + temp0
    
    return f0_x
  
  def f1_x(self, x):
    temp1 = 0
    temp1 = self.group.init(ZR, int(temp1))
    for j in range(1, t_0): # The original formula sums from 1 to t0-1, i.e., i from 0 to t0-2; in fact, it should be a randomly selectable a0 and a1 here, rather than the first t0-1 in order.
      j_zr = self.group.init(ZR, int(j))
      temp1 += self.a1[j - 1] * (x ** j_zr)
    f1_x = self.d + temp1
    
    return f1_x
  
  @measure_time
  def keygen(self):
    # Create a vector of length 5
    self.x = [self.group.random(ZR) for _ in range(n)]
    self.a0 = [self.group.random(ZR) for _ in range(t_0 - 1)]
    self.a1 = [self.group.random(ZR) for _ in range(t_0 - 1)]    
    self.ID = [generate_random_binary_string(100) for _ in range(n)]
    
    # initialisation
    self.r_list = []
    self.d_list = []
    self.y_list = []
    self.Q_list = []
    self.theta_list = []
    
    for i in range(n):
      # x = i
      # x = self.group.init(ZR, int(x))
      # r = self.f0_x(x) # the secret key of group member ID_i
      # d = self.f1_x(x) # the secret key of group member ID_i
      r = self.f0_x(self.x[i]) # the secret key of group member ID_i
      d = self.f1_x(self.x[i]) # the secret key of group member ID_i
      y = self.h ** r # the public key of group member ID_i
      Q = H0(self.ID[i]) # the public key of group member ID_i
      theta = Q ** self.a # the secret key of group member ID_i
      
      self.r_list.append(r)
      self.d_list.append(d)
      self.y_list.append(y)
      self.Q_list.append(Q)
      self.theta_list.append(theta)

  # # constructive polynomial p_i(x) = p_bar_i0 + p_bar_i1*x +... + p_bar_{t1 - 1}*x^{t1 - 1}
  # def poly(self, x):
  #   result = 0
  #   for idx, coeff in enumerate(self.coefficients):
  #     result += coeff * (x ** idx)
  #   return result

  def distributed_key_generation(self, eta, t1):
    """
    Execute the distributed key generation algorithm
    :param eta: parameter related to the number of servers, corresponds to η in the algorithm
    :param t1: polynomial count parameter, corresponds to t1 in the algorithm.
    :return: results of si, Vi, V_KS, etc. for each server, here we simply return the key data in list form
    """
    
    # Store data related to each KS_i, elements are dictionaries containing si, Vi, etc.
    ks_data_list = []
    # Step 1: select parameters and construct polynomials for each KS_i
    p_bar_list = [] # Store the constant terms p_bar_i0 for the ith KS in order.
    all_coefficients = [] # Store the coefficients for the ith KS in order
    for i in range(eta):
      p_bar_i0 = self.group.random(ZR)
      p_bar_list.append(p_bar_i0)
      coefficients = [p_bar_i0]
      all_coefficients.append(p_bar_i0)
      for j in range(t1-1):

        coeff = self.group.random(ZR)
        coefficients.append(coeff)
        all_coefficients.append(coeff)
        
        # print(f"---------i:{i}, j:{j}---------")
        # print(f"p_bar_list:{p_bar_list}")
        # print(f"coefficients:{coefficients}")
        # print(f"all_coefficients:{all_coefficients}")
      
      # constructive polynomial p_i(x) = p_bar_i0 + p_bar_i1*x +... + p_bar_{t1 - 1}*x^{t1 - 1}
      def poly(x, i):
        result = 0
        x = x
        i = i - 1
        for k in range(t1):
          result += all_coefficients[i * t1 + k] * (x ** k)
        return result


    
    # Step 2: Each KS_i calculates and sends the relevant data (simplified here, not actually implementing network sending, just simulating the calculation)
    g_p_bar_list = []
    for i in range(eta):
      g_p_bar = [pow(self.g, all_coefficients[i * t1 + k]) for k in range(t1)]
      g_p_bar_list.append(g_p_bar)
    #   for k in range(t1):
    #     print(f"-------i:{i}, k:{k}---all_coefficients[i * t1 + k]:{all_coefficients[i * t1 + k]}--------------------")
    # print(f"------------------------g_p_bar_list:{g_p_bar_list}-----------------------\n")
    # Simulate secretly sending p_i(j) to other KS_j, omit the actual communication here and use it directly in the subsequent verification
    # If the actual scenario, need to resort to secure channels and other mechanisms

    # Step 3: Each KS_i is validated
    valid = True
    for i in range(1, eta+1):
      print(f"--------------The i:{i}th KS starts to validate the--------------")
      for j in range(1, eta+1):
        # print(f"--------------The j:{j}th epoch--------------")
        if i == j:
          continue
        left = pow(self.g, poly(i, j))
        # print(f"left:{left}")

        right = 1
        for k in range(t1):
          # print(f"--------------The k:{k}th epoch--------------")
          # right *= pow(g_p_bar_list[j-1][k], i ** k)
          # print(f"right0000000000:{right}")
          # right = 1
          right *= pow(pow(self.g, all_coefficients[(j-1) * t1 + k]), i ** k)
          # print(f"left:{left}")
          # print(f"right:{right}")
        if left != right:
          # print(f"left:{left}")
          # print(f"right:{right}")
          valid = False
          break
      if not valid:
        break
    if not valid:
      raise ValueError("Validation failed, there is a problem with the generation process")
    else:
      print(f"Verify Success")

    # Step 4: Calculate si and Vi
    s_list = []
    V_list = []
    for i in range(1, eta + 1):
      s_i = 0
      for k in range(1, eta + 1):
        s_i += poly(i, k)
        
      s_list.append(s_i)
      V_i = pow(self.g, s_i)
      V_list.append(V_i)

    # Step 5: Calculate V_KS and collate results
    V_KS = 1
    for p_bar in p_bar_list:
      # print(f"p_bar: {p_bar}")
      V_KS *= pow(self.g, p_bar)
      # print(f"V_KS: {V_KS}")

    for i in range(eta):
      ks_data = {
        "si": s_list[i],
        "Vi": V_list[i],
        "V_KS": V_KS
      }
      ks_data_list.append(ks_data)

    # return ks_data_list
    return s_list, V_list, V_KS

  # Generate server-derived keywords
  def server_derived_keyword_generation(self, w_j, s_list, V_list, V_KS, eta, t1):
    # Step 1: S selects alpha, computes W = H0(w_j)^alpha, sends to W_S
    alpha = self.group.random(ZR)  # select α
    W =  H0(w_j) ** alpha  # compute W
    # print(f"W = H0_wj ** alpha: {W}")
    # self.W_S.receive_W_from_S(W, w_j) # W_S received

    # Step 2: W_S selects beta, re-randomizes W to W' = W^beta, sends to KSi
    beta = self.group.random(ZR)
    W_prime = W ** beta  #  compute W' = W^β blind signature
    # for i in range(1, eta+1):
    #   KSi.receive_W_prime_from_WS(W_prime)

    # Step 3: KSi signs W' to get σ'_i = W'^s_i, forwards to W_S
    sigmas_prime_list = []
    for i in range(1, eta + 1):
      sigma_prime_i = W_prime ** s_list[i - 1]
      sigmas_prime_list.append(sigma_prime_i)
      # self.W_S.receive_sigma_prime_from_KSi(sigma_prime_i)

    # Step 4: W_S de-randomizes to get σ_i = σ'_i^(beta^-1), sends to S
    sigmas_list = []
    beta_inv = pow(beta, -1)
    for i in range(1, eta + 1):
      sigma_i = sigmas_prime_list[i - 1] ** beta_inv
      sigmas_list.append(sigma_i)
      # self.S.receive_sigma_from_WS(sigma_i, w_j)

    # Step 5: S verifies signatures and computes σ_wj
    self.valid_sigmas = []
    
    for i in range(1, t1 + 1):  # Take the first t1 signatures to verify
      # print(f"sigma_i:{sigmas_list[i - 1]}")
      # print(f"bilinear_pairing(sigma_i, self.g):{bilinear_pairing(sigmas_list[i -1], self.g)}")
      # print(f"bilinear_pairing(W, self.group.random(G1)):{bilinear_pairing(W, V_list[i - 1])}")
      
      if bilinear_pairing(sigmas_list[i - 1], self.g) == bilinear_pairing(W, V_list[i - 1]):
        self.valid_sigmas.append(sigmas_list[i - 1])
    if len(self.valid_sigmas) < t1:
      print(f"len(valid_sigmas): {len(self.valid_sigmas)}")
      raise ValueError("Signature verification failed with insufficient number of legitimate signatures")
    else:
      print("Signature Verification Successful")

    # Calculate the product and correlation coefficient
    product_sigma = self.group.init(G1, 1)
    # print(f"product_sigma:{product_sigma}")
    for k in range(1, t1 + 1):
      l_k = 1 
      l_k = self.group.init(ZR, int(l_k))
      
      for j in range(1, t1 + 1):
        if j != k:
          j_zr = self.group.init(ZR, int(j))
          k_zr = self.group.init(ZR, int(k))
          l_k *= j_zr / (j_zr - k_zr)
      print(f"l_k:{l_k}")
      # print(f"self.valid_sigmas[k - 1]:{self.valid_sigmas[k - 1]}")
      # If valid_sigmas[k - 1] is the type of the encryption library, initialise it using the method provided by the library
      # valid_sigmas_g1 = self.group.init(G1, valid_sigmas[k - 1])  # Convert to G1 type
      
      # l_k_zr = self.group.init(ZR, int(l_k))
      # # l_k_zr = self.group.hash(l_k, ZR)
      # print(f"l_k_zr:{l_k_zr}")
      
      # product_sigma *= valid_sigmas_g1 ** l_k_zr
      # product_sigma *= pow(valid_sigmas[k - 1], l_k_zr)
      product_sigma *= pow(self.valid_sigmas[k - 1], l_k)
    print(f"product_sigma:{product_sigma}")
    alpha_inv = pow(alpha, -1)
    # print(f"alpha_inv:{alpha_inv}")
    sigma_wj = product_sigma ** alpha_inv

    # final verification
    if bilinear_pairing(sigma_wj, self.g) != bilinear_pairing(H0(w_j), V_KS):
      # print(f"bilinear_pairing(sigma_wj, self.g):{bilinear_pairing(sigma_wj, self.g)}")
      # print(f"bilinear_pairing(H0(w_j), V_KS:{bilinear_pairing(H0(w_j), V_KS)}")
      raise ValueError("Final Signature Verification Failure")
    else:
      print("Final Signature Verification Successful")
      # print(f"bilinear_pairing(sigma_wj, self.g):{bilinear_pairing(sigma_wj, self.g)}")
      # print(f"bilinear_pairing(H0(w_j), V_KS:{bilinear_pairing(H0(w_j), V_KS)}")

    # Step 6: calculate server-derived keyword
    key_H1 = H1(sigma_wj)
    
    # If the condition is satisfied then calculate sdk_wj
    sdk_w_j = PRF(key_H1, w_j)
    return sdk_w_j


  def Unbiased_randomness_generation(self):
    # W_S
    b0 = self.group.random(ZR)
    b1 = self.group.random(ZR)
    c = H2(b0, b1)  # sends c to S
    
    # S
    b2 = self.group.random(ZR) 
    B = self.omega1 ** b2  # sends B to W_S
    
    # W_S
    V = B * (self.omega1 ** b0)
    
    # S
    if H2(b0, b1) != c:
      raise ValueError("---- validation failure ---- H2(b0, b1) != c ------")
    else:
      print("---- Verify Success ---- H2(b0, b1) == c ------")
      mu = b0 + b2
    
    return mu, V


  def File_indexes_ciphertexts_and_tags_construction(self, mu, V, sdk_w_j):
    # S
    # zero = 0
    # zero = self.group.init(ZR, int(zero))
    # print(f"self.h ** zero:{self.h ** (mu - mu)}")
    self.I_prime_0 = self.h ** ( - mu)
    self.I_prime_1 = self.omega1 ** mu
    self.I_j = self.omega2 ** (mu * H3(sdk_w_j))
    
    # b, Vb = self.Unbiased_randomness_generation()
    # e, Ve = self.Unbiased_randomness_generation()
    # z, Vz = self.Unbiased_randomness_generation()
    # C0 = self.g ** b
    
    
    
    
    
    # W_S
    if self.I_prime_1 != V:
      raise ValueError("---- validation failure ---- self.I_prime_1 != V ------")
    else:
      print("---- Verify Success ---- self.I_prime_1 == V ------")
      #  W_S forwards (I, C, {tagi,m}) to CS.


  def TrapGen(self, sdk_w_tilde, t1):
    psi = self.group.random(ZR)
    A = self.g ** psi
    B = self.h ** (self.u * H3(sdk_w_tilde) + psi)
    
    LAMBDA_list = []
    THETA_list = []
    T1 = self.group.init(G1, 1)
    T2 = self.group.init(G1, 1)
    # T1 = 1
    # T2 = 1
    
    temp_r = 0
    temp_r = self.group.init(ZR, int(temp_r))

    for j in range(1, t_0 + 1):
      DELTA = 1
      # DELTA = self.group.init(ZR, int(DELTA))
      
      for i in range(1, t_0 + 1):
        if i != j:
          i_zr = self.group.init(ZR, int(i))
          j_zr = self.group.init(ZR, int(j))
          temp = i_zr / (i_zr - j_zr)
          temp = self.x[i-1] / (self.x[i-1] - self.x[j-1])
          # temp = i / (i - j)
          DELTA = temp * DELTA
      print(f"DELTA:{DELTA}")
      
      DELTA = self.group.init(ZR, int(DELTA))
      LAMBDA = A ** (DELTA * self.r_list[j - 1])
      THETA = B ** (DELTA * self.d_list[j - 1])
      # LAMBDA = A ** (DELTA * self.r)
      # THETA = B ** (DELTA * self.d)
      LAMBDA_list.append(LAMBDA)
      THETA_list.append(THETA)
      
      
      temp_r += DELTA * self.f0_x(self.x[j - 1])
      # temp_r += DELTA * self.f0_x(j - 1)

      T1 *= LAMBDA
      T2 *= THETA
    print(f"T1:{T1}")
    print(f"T2:{T2}")
    T1 = A ** self.r
    T2 = B ** self.d
    print(f"T1:{T1}")
    print(f"T2:{T2}")
    
    test_r = temp_r
    
    if self.r != test_r:
      print(f"self.r:{self.r}")
      print(f"test_r:{test_r}")
      raise ValueError("---- validation failure ---- self.r != test_r ------")
    else:
      print("---- Verify Success ---- self.r == test_r ------")
      print(f"self.r:{self.r}")
      print(f"test_r:{test_r}")
    
    return T1, T2


    
  def Search(self, T1, T2):
    pairing_left = pair(self.I_prime_0, T1) * pair(self.I_prime_1, T2)
    pairing_right = pair(self.I_j, self.h)
    
    
    
    # CS
    if pairing_left != pairing_right:
      print(f"pairing_left: {pairing_left}")
      print(f"pairing_right: {pairing_right}")
      raise ValueError("---- validation failure ---- pairing_left != pairing_right ------")
    else:
      print("---- Verify Success ---- pairing_left == pairing_right ------")
      print(f"pairing_left: {pairing_left}")
      print(f"pairing_right: {pairing_right}")
      #  CS outputs the corresponding results {idm, C_̃m} to TPA.


if __name__ == "__main__": # Used to test Distributed Key Generation.
  group = PairingGroup("SS512")
  pcse = PCSE(group)
  pcse.keygen()
  s_list = []
  V_list = []
  # try:
  #   result = pcse.distributed_key_generation(eta, t_1)
  #   print(f"result:{result}")
  #   for idx, data in enumerate(result):
  #     print(f"Keyword Server {idx + 1} data: {data}")
  # except ValueError as e:
  #   print(f"error: {e}")

  try:
    s_list, V_list, V_KS = pcse.distributed_key_generation(eta, t_1)
    # print(f"s_list:{s_list}")
    # print(f"V_list:{V_list}")
    # print(f"V_KSt:{V_KS}")
  except ValueError as e:
    print(f"error: {e}")
  
  m = "This is a message. The keyword is example_keyword."
  w_j = "example_keyword"
  sdk_wj = pcse.server_derived_keyword_generation(w_j, s_list, V_list, V_KS, eta, t_1)
  print(f"sdk_w_j: {sdk_wj}")


  mu, V = pcse.Unbiased_randomness_generation()
  print (f"mu: {mu}")
  print (f"V: {V}")
  pcse.File_indexes_ciphertexts_and_tags_construction(mu, V, sdk_wj)
  
  # w_tilde_j = "another_keyword"
  w_tilde_j = "example_keyword"
  # print(f"Server derived keyword for {w_j}: {sdk_wj}")
  sdk_w_tilde = pcse.server_derived_keyword_generation(w_tilde_j, s_list, V_list, V_KS, eta, t_1)
  print(f"sdk_w_tilde: {sdk_w_tilde}")
  
  T1, T2 = pcse.TrapGen(sdk_w_tilde, t_1)
  
  pcse.Search(T1, T2)
  
  # sss = group.random(ZR)
  # ddd = "example_keyword"
  # fff = "example_keyword"
  # print(f"PRF(sss, fff): {PRF(sss, fff)}")
  # print(f"PRF(sss, fff): {PRF(sss, fff)}")
  