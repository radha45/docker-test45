FROM python:3


RUN pip install boto3

RUN pip install awscliv2

ADD . /

WORKDIR /
RUN git clone https://github.com/wolfcw/libfaketime.git
WORKDIR /libfaketime/src
RUN make install
CMD  ["export", "LD_PRELOAD=/usr/local/lib/faketime/libfaketime.so.1"]
# ENTRYPOINT ["python"]
WORKDIR /
ADD . /