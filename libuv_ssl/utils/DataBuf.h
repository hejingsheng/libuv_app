#ifndef _DATA_BUF_H_
#define _DATA_BUF_H_

const int MAX_DATA_LEN = 8192;

enum RingBufErrorCode
{
	ERROR_NOT_HAVE_SPACE = -2,
	ERROR_NOT_HAVE_DATA = -1,
};

class DataRingBuf
{
public:
	DataRingBuf(int size = 0);
	virtual ~DataRingBuf();

public:
	int writeData(const char *data, int len);
	int readData(char *data, int size);
	char* getWritePtrAndLeft(int &left);
	int getUsed() const;
	bool isFull() const;
	bool isEmpty() const;
	int addRingBufSpace(int addSize);
	void clear();

private:
	char *buf_;
	int r_Pos_;
	int w_Pos_;
	int length_;
};

#endif
