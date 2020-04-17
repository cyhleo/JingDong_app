from mitmproxy import http

from pymongo import MongoClient
import collections
import random
from enum import Enum
# 导入日志模块
from mitmproxy import ctx
from mitmproxy.exceptions import TlsProtocolException
from mitmproxy.proxy.protocol import TlsLayer, RawTCPLayer
import mitmproxy
import json
import re


class get_comments(object):
    def __init__(self):
        self.mongo = Mongo()
        self.id = 0

    def response(self,flow:mitmproxy.http.HTTPFlow):

        url1 = 'getCommentListWithCard'
        url2 = 'getFoldCommentList'
        if url1 in flow.request.url:
            text = flow.response.text
            json_data = json.loads(text)
            id_str = json_data.get("tagStatisticsinfoList")[0].get("ckeKeyWordBury")

            self.id = re.search('sku=(\d+)', id_str).group(1)
            info_list = json_data.get("commentInfoList")
            for info_dict in info_list:
                try:
                    comment_dict = {'id': self.id}
                    commentInfo = info_dict.get("commentInfo")
                    comment_dict['nickname'] = commentInfo.get('userNickName')
                    comment_dict['data'] = commentInfo.get('commentDate')
                    try:
                        comment_dict['text'] = commentInfo.get('commentData')
                    except:
                        comment_dict['text'] = None
                    try:
                        pic_url = commentInfo.get('pictureInfoList')
                        pic_url_list = []
                        for pic_dict in pic_url:
                            url = pic_dict.get('picURL')
                            pic_url_list.append(url)
                        comment_dict['pic_url'] = pic_url_list
                    except:
                        # 该评论没有照片
                        comment_dict['pic_url'] = None
                    self.mongo.save(comment_dict)
                except:
                    # 该条数据没有评论,或该评论没有文字
                    pass

        elif url2 in flow.request.url:
            text = flow.response.text
            json_data = json.loads(text)
            info_list = json_data.get("commentInfoList")

            for info_dict in info_list:
                try:
                    comment_dict = {'id': self.id}
                    comment_dict['nickname'] = info_dict.get('userNickName')
                    comment_dict['data'] = info_dict.get('commentDate')
                    try:
                        comment_dict['text'] = info_dict.get('commentData')
                    except:
                        comment_dict['text'] = None

                    try:
                        pic_url = info_dict.get('pictureInfoList')
                        pic_url_list = []
                        for pic_dict in pic_url:
                            url = pic_dict.get('picURL')
                            pic_url_list.append(url)
                        comment_dict['pic_url'] = pic_url_list
                    except:
                        comment_dict['pic_url'] = None
                    self.mongo.save(comment_dict)
                except:
                    pass


class Mongo(object):
    def __init__(self):
        self.client = MongoClient('')
        self.collection = self.client['']
        self.db = self.collection['']
    def save(self,comment_dict):
        self.db.update({'nickname': comment_dict.get('nickname'),'data':comment_dict.get('data')}, {'$set': comment_dict}, True)

addons=[
    get_comments()
]

# -------------------------------------------------------------------
# 解决error‘Cannot establish TLS with client’
class InterceptionResult(Enum):
    success = True
    failure = False
    skipped = None


class _TlsStrategy:
    """
    Abstract base class for interception strategies.
    """

    def __init__(self):
        # A server_address -> interception results mapping
        # collections.defaultdict 相当于字典
        # collections.deque(maxlen=200)为最大长度为200的队列
        self.history = collections.defaultdict(lambda: collections.deque(maxlen=200))

    def should_intercept(self, server_address):
        """
        Returns:
            True, if we should attempt to intercept the connection.
            False, if we want to employ pass-through instead.
        """
        raise NotImplementedError()

    def record_success(self, server_address):
        self.history[server_address].append(InterceptionResult.success)

    def record_failure(self, server_address):
        self.history[server_address].append(InterceptionResult.failure)

    def record_skipped(self, server_address):
        self.history[server_address].append(InterceptionResult.skipped)


class ConservativeStrategy(_TlsStrategy):

    """
    Conservative Interception Strategy - only intercept if there haven't been any failed attempts
    in the history.

    """

    def should_intercept(self, server_address):
        if InterceptionResult.failure in self.history[server_address]:
            return False
        return True


class ProbabilisticStrategy(_TlsStrategy):
    """
    Fixed probability that we intercept a given connection.
    """
    def __init__(self,
 p):
        self.p = p
        super(ProbabilisticStrategy, self).__init__()

    def should_intercept(self, server_address):
        # random.uniform(0, 1)：取0-1的随机小数
        return random.uniform(0, 1) < self.p


class TlsFeedback(TlsLayer):
    """
    Monkey-patch _establish_tls_with_client to get feedback if TLS could be established
    successfully on the client connection (which may fail due to cert pinning).
    """

    def _establish_tls_with_client(self):
        server_address = self.server_conn.address

        try:
            super(TlsFeedback, self)._establish_tls_with_client()
        except TlsProtocolException as e:
            tls_strategy.record_failure(server_address)
            raise e
        else:
            tls_strategy.record_success(server_address)


# inline script hooks below.

tls_strategy = None


def load(l):
    l.add_option(
        "tlsstrat", int, 0, "TLS passthrough strategy (0-100)",
    )


def configure(updated):
    global tls_strategy
    if ctx.options.tlsstrat > 0:
        tls_strategy = ProbabilisticStrategy(float(ctx.options.tlsstrat) / 100.0)
    else:
        tls_strategy = ConservativeStrategy()


def next_layer(next_layer):
    """
    This hook does the actual magic - if the next layer is planned to be a TLS layer,
    we check if we want to enter pass-through mode instead.
    """
    if isinstance(next_layer, TlsLayer) and next_layer._client_tls:
        server_address = next_layer.server_conn.address

        if tls_strategy.should_intercept(server_address):
            # We try to intercept.
            # Monkey-Patch the layer to get feedback from the TLSLayer if interception worked.
            next_layer.__class__ = TlsFeedback
        else:
            # We don't intercept - reply with a pass-through layer and add a "skipped" entry.
            mitmproxy.ctx.log("TLS passthrough for %s" % repr(next_layer.server_conn.address), "info")
            next_layer_replacement = RawTCPLayer(next_layer.ctx, ignore=True)
            next_layer.reply.send(next_layer_replacement)
            tls_strategy.record_skipped(server_address)

# ---------------------------------------------------------------------


