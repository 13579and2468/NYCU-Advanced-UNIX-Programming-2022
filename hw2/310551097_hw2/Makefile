all : logger.so logger

logger.so : wrapper.cpp
	g++ -o logger.so -g3 -shared -fPIC wrapper.cpp -ldl

logger : hw2.c
	gcc -o logger -g3 hw2.c

clean:
	rm logger
	rm logger.so
