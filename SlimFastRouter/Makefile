CXX := g++

CXXFLAGS := -std=c++0x 

CXX_LDFLAGS := -L/usr/lib -lssl -lcrypto -pthread 

%.o: %.c
	$(CXX) $(CXXFLAGS) -c $< -o $@
	
slimfastrouter: SlimFastRouter.c timeDiff.c tpool.c chainingHashTable.c ipMappingChainingHashTable.c crypto.cpp HashTable.c
	$(CXX) $(CXXFLAGS) $^ -o $@ $(CXX_LDFLAGS)

clean:
	rm -f *.so *.o SlimFastRouter slimfastrouter
# 	SlimFastRouter is unix socket