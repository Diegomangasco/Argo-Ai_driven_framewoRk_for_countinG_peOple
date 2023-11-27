import numpy
from bloomfilter import BloomFilter

"""
Created on Sat Oct 21 12:25:45 2023

@author: LordAssalt
"""

def calculate_num_of_stored_element(bf: BloomFilter) -> float:
    """
    Calculate the number of element in a Bloom Filter.

    :param bf: Bloom Filter
    :return: Float value that can easily be parsed as int, indicating the number of element in the Bloom Filter
    """

    n = bf.get_n()
    N1 = bf.get_m()
    k = bf.get_k()
    ln_arg = (1 - (N1 / n))

    return (-n / k) * (numpy.log(ln_arg))


def calculate_num_of_element_in_intersection(bf1: BloomFilter, bf2: BloomFilter, bfi: BloomFilter) -> float:
    """
    Calculate the number of element in the intersection of 2 Bloom Filters.

    :param bf1: Bloom Filter 1
    :param bf2: Bloom Filter 2
    :param bfi: Intersection of Bloom Filter
    :return: Float value that can easily be parsed as int, indicating the number of element in the Bloom Filter Intersection
    """

    n = bfi.get_n()
    Ni = bfi.get_m()
    k = bfi.get_k()
    N1 = bf1.get_m()
    N2 = bf2.get_m()

    num = (Ni * n) - (N1 * N2)
    den = n - N1 - N2 + Ni

    ln_arg1 = numpy.log(n - (num / den))
    ln_arg2 = numpy.log(n)
    ln_arg3 = numpy.log(1 - (1 / n))

    return (ln_arg1 - ln_arg2) / (k * ln_arg3)


def calculate_intersection_of_bf(bf1: BloomFilter, bf2: BloomFilter) -> BloomFilter:
    """
    Calculate intersection between Bloom Filter 1 and Bloom Filter 2.

    :param bf1: Bloom Filter 1
    :param bf2: Bloom Filter 2
    :return: Result of Intersection
    """

    if bf1.get_n() != bf2.get_n() or bf1.get_k() != bf2.get_k():
        raise
    bfi = BloomFilter(bf1.get_n(), bf1.get_k())
    bfi.set_data(bf1.bit_array & bf2.bit_array)

    return bfi
