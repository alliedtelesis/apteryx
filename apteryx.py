
from ctypes import *

apteryx = cdll.LoadLibrary('libapteryx.so')

apteryx_set = apteryx.apteryx_set
apteryx_set.restype = c_bool

apteryx_get = apteryx.apteryx_get
apteryx_get.restype = c_char_p

apteryx_search = apteryx.apteryx_search_simple
apteryx_search.restype = c_char_p

apteryx.apteryx_init(False)