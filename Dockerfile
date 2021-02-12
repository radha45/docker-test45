FROM python:3


RUN pip install boto3

RUN pip install awscliv2
RUN pip install pymysql

ADD . /

WORKDIR /
RUN git clone https://github.com/wolfcw/libfaketime.git
WORKDIR /libfaketime/src
RUN make install
EXPOSE 3306
RUN export LD_PRELOAD=/usr/local/lib/faketime/libfaketime.so.1
WORKDIR /
ADD . /
ENTRYPOINT ["python","scp-test.py"]
CMD [""]
