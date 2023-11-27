"""
Created on Sat Oct 21 12:25:45 2023

@author: LordAssalt
"""

# Python 3 program to build Bloom Filter
# import json
import math
import mmh3
import numpy
from numpy import random
from bitarray import bitarray
# import requests


class BloomFilter(object):
    """
    Class for Bloom filter, using murmur3 hash function
    """

    def __init__(self, n, k):
        """
        Declarate a new Bloom Filter.

		:param n: Dimension in bit of the Filter
		:param k: Number of hash function to use
		:return: None
		"""

        # Size of bit array to use
        self.n = n

        # Number of hash functions to use
        self.k = k

        # Number of bit at 1 in the filter
        self.m = 0

        # Number of element stored in the filter
        self.num_elem = 0

        # Bit array of given size
        self.bit_array = bitarray(self.n)

        # initialize all bits as 0
        self.bit_array.setall(0)

    def add(self, item) -> None:
        """
		Add an item in the filter.

		:param item: Element to be inserted
		:return: None
		"""

        digests = []
        self.num_elem += 1
        for i in range(self.k):
            # create digest for given item.
            # i work as seed to mmh3.hash() function
            # With different seed, digest created is different
            digest = mmh3.hash(item, i) % self.n
            digests.append(digest)

            # set the bit True in bit_array
            self.bit_array[digest] = True
        self.m = self.bit_array.count(1)

    def check(self, item) -> bool:
        """
		Check for existence of an item in filter.

		:param item: Element to verify
		:return: Boolean value, True the element is in the Bloom Filter, False otherwise
		"""

        for i in range(self.k):
            digest = mmh3.hash(item, i) % self.n
            if self.bit_array[digest] == False:
                # if any of bit is False then,its not present
                # in filter
                # else there is probability that it exist
                return False
        return True

    def reset(self) -> None:
        """
		Reset the Bloom Filter.

		:return: None
		"""

        self.m = 0
        self.num_elem = 0
        self.bit_array.setall(0)

    def set_data(self, bitarr) -> None:
        """
        Set new data into a Bloom Filter. The count of element is approximated.

        :param bitarr: Array of bit to put into the Bloom Filter
        """
        
        if len(bitarr) != self.n:
            raise

        self.bit_array = bitarr
        self.m = self.bit_array.count(1)
        ln_arg = (1 - (self.m / self.n))
        self.num_elem = int((-self.n / self.k) * (numpy.log(ln_arg)))

    def get_k(self) -> int:
        """
		Get the number of hash function used.

		:return: Integer number of hash function used
		"""

        return self.k

    def get_m(self) -> int:
        """
		Get the number of 1 in the Bloom Filter.

		:return: Integer number of 1 in Bloom Filter
		"""

        return self.m

    def get_data(self) -> str:
        """
        Get the array of 1 and 0 of the Bloom Filter.

        :return: str
        """

        return self.bit_array.to01()

    def get_n(self) -> int:
        """
		Get the dimension in bit of the Bloom Filter.

		:return: Integer number regarding the dimension of the Bloom Filter
		"""

        return self.n

    def get_num_elem(self) -> int:
        """
		Get the number of element stored in the Bloom Filter.

		:return: Integer number of stored element in the Bloom Filter
		"""

        return self.num_elem

    def calculate_fp_probability(self) -> float:
        """
        Calculate the false positive probability for a given Bloom Filter.

        :return: Float number in [0,1] that represent the false positive probability
        """
        return pow((self.get_m() / self.get_n()), self.get_k())

    def calculate_gamma_deniability(self):
        """
        Get the gamma value for Bloom Filter deniability.

		:return: Float number in [0,1] that represent the probability
        """

        k = self.get_k()
        m = self.get_n()
        n = self.get_num_elem()
        v = ((pow(2, 48) - n) * (pow((1 - math.exp((-1 * k * n) / m)), k)))
        arg = (1 - math.exp(((-1 * v * k) / (m * (1 - math.exp((-k * n) / m))))))
        return pow(arg, k)


    def anonymization_noise(self, dim) -> None:
        """
        Fill the Bloom Filter with a noise.

        :dim: Random MACs to be added
        :return: None
        """

        for i in range(dim):
            arr_of_ones = random.randint(self.n, size=self.k)
            for val in arr_of_ones:
                self.bit_array[val] = True
            self.m = self.bit_array.count(1)
            self.num_elem += 1
            
        return None
    
    def compress(self) -> str:
        """
        Compress the Bloom Filter

        :return: str
        """
        
        s = ""
        last = -1
        counter = 0
        for i in range(0, self.n):
            if last == -1:
                last = self.bit_array[i]
                counter += 1
            elif last == self.bit_array[i]:
                counter += 1
            else:
                s = s.join(f"{last}:{counter},")
                counter = 1
                last = self.bit_array[i]
        
        return s
        
        
        