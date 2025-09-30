package com.bitget.openapi.ws;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.bitget.openapi.common.enums.SignTypeEnum;
import com.bitget.openapi.common.utils.DateUtil;
import com.bitget.openapi.common.utils.SignatureUtils;
import com.bitget.openapi.dto.request.ws.SubscribeReq;
import com.bitget.openapi.dto.request.ws.WsBaseReq;
import com.bitget.openapi.dto.request.ws.WsLoginReq;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;

import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.zip.CRC32;

@Slf4j
public class BitgetWsHandle implements BitgetWsClient {
    public static final String WS_OP_LOGIN = "login";
    public static final String WS_OP_SUBSCRIBE = "subscribe";
    public static final String WS_OP_UNSUBSCRIBE = "unsubscribe";

    private WebSocket webSocket;
    private volatile boolean loginStatus = false;
    private volatile boolean connectStatus = false;
    private volatile boolean reconnectStatus = false;

    private BitgetClientBuilder builder;
    private Map<SubscribeReq, SubscriptionListener> scribeMap = new ConcurrentHashMap<>();
    private Map<SubscribeReq, BookInfo> allBook = new ConcurrentHashMap<>();

    private Set<SubscribeReq> allSuribe = Collections.synchronizedSet(new HashSet<>());

    private BitgetWsHandle(BitgetClientBuilder builder) {
        this.builder = builder;
        webSocket = initClient();
    }

    private WebSocket initClient() {
        OkHttpClient client = new OkHttpClient.Builder()
                .writeTimeout(60, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .connectTimeout(60, TimeUnit.SECONDS)
                .proxy(builder.proxy)
                .build();

        Request request = new Request.Builder()
                .url(builder.pushUrl)
                .build();

        webSocket = client.newWebSocket(request, new BitgetWsListener(this));

        if (builder.isLogin) {
            login();
        }
        log.info("开始连接WebSocket服务器...");
        while (!connectStatus) {
        }

        return webSocket;
    }

    public static BitgetClientBuilder builder() {
        return new BitgetClientBuilder();
    }

    @Override
    public void sendMessage(WsBaseReq<?> req) {
        sendMessage(JSONObject.toJSONString(req));
    }

    @Override
    public void sendMessage(String message) {
        webSocket.send(message);
    }

    @Override
    public void unsubscribe(List<SubscribeReq> channels) {
        allSuribe.removeAll(channels);
        channels.forEach(channel -> {
            scribeMap.remove(channel);
        });
        sendMessage(new WsBaseReq<>(WS_OP_UNSUBSCRIBE, channels));
    }

    @Override
    public void subscribe(List<SubscribeReq> channels) {
        if (CollectionUtils.isNotEmpty(channels)) {
            for (SubscribeReq subscribeReq : channels) {
                if (subscribeReq != null && StringUtils.isBlank(subscribeReq.getCoin())) {
                    subscribeReq.setCoin(subscribeReq.getInstId());
                }
            }
        }

        allSuribe.addAll(channels);
        sendMessage(new WsBaseReq<>(WS_OP_SUBSCRIBE, channels));
    }

    @Override
    public void subscribe(List<SubscribeReq> channels, SubscriptionListener listener) {
        channels.forEach(channel -> {
            scribeMap.put(channel, listener);
        });
        subscribe(channels);
    }

    @Override
    public void login() {
        Validate.notNull(builder.apiKey, "apiKey is null");
        Validate.notNull(builder.secretKey, "secretKey is null");
        Validate.notNull(builder.passPhrase, "passphrase is null");

        List<WsLoginReq> args = buildArgs();
        sendMessage(new WsBaseReq<>(WS_OP_LOGIN, args));
        //休眠1s，等待登录结果
        log.info("开始WebSocket登录流程...");
        while (!this.loginStatus) {
            try {
                Thread.sleep(10000);
                args = buildArgs();
                sendMessage(new WsBaseReq<>(WS_OP_LOGIN, args));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        log.info("WebSocket登录成功");
    }

    @Override
    public void close() {
        if (webSocket != null) {  // 增加空值判断
            webSocket.close(1000, "close");
            webSocket = null;
        }
    }

    private List<WsLoginReq> buildArgs() {
        String timestamp = Long.valueOf(Instant.now().getEpochSecond()).toString();
        String sign = sha256_HMAC(timestamp, builder.secretKey);
        if (SignTypeEnum.RSA == builder.signType) {
            sign = ws_rsa(timestamp, builder.secretKey);
        }

        WsLoginReq loginReq = WsLoginReq.builder().apiKey(builder.apiKey).passphrase(builder.passPhrase).timestamp(timestamp).sign(sign).build();

        List<WsLoginReq> args = new ArrayList<WsLoginReq>() {{
            add(loginReq);
        }};
        return args;
    }

    private void sleep(long s) {
        try {
            Thread.sleep(s);
        } catch (Exception e) {

        }
    }

    private String sha256_HMAC(String timeStamp, String secret) {
        String hash = "";
        try {
            hash = SignatureUtils.wsGenerateSign(timeStamp, secret);
        } catch (Exception e) {
            throw new RuntimeException("sha256_HMAC error", e);
        }
        return hash;
    }

    private String ws_rsa(String timeStamp, String secret) {
        String hash = "";
        try {
            hash = SignatureUtils.wsGenerateRsaSignature(timeStamp, secret);
        } catch (Exception e) {
            throw new RuntimeException("sha256_HMAC error", e);
        }
        return hash;
    }

    private final class BitgetWsListener extends WebSocketListener {

        ScheduledExecutorService service;
        private BitgetWsClient bitgetWsClient;

        public BitgetWsListener(BitgetWsClient bitgetWsClient) {
            this.bitgetWsClient = bitgetWsClient;
        }

        @Override
        public void onOpen(final WebSocket webSocket, final Response response) {
            connectStatus = true;
            reconnectStatus = false;
            //连接成功后，设置定时器，每隔25s，自动向服务器发送心跳，保持与服务器连接
            Runnable runnable = () -> {
                // task to run goes here
                bitgetWsClient.sendMessage("ping");
            };

            service = Executors.newSingleThreadScheduledExecutor();
            // 第二个参数为首次执行的延时时间，第三个参数为定时执行的间隔时间
            service.scheduleAtFixedRate(runnable, 25, 25, TimeUnit.SECONDS);
        }

        @Override
        public void onClosing(WebSocket webSocket, int code, String reason) {
            log.info("连接即将断开！");
            close();
            if (!reconnectStatus) {
                reConnect();
            }

        }

        @Override
        public void onClosed(final WebSocket webSocket, final int code, final String reason) {
            log.info("连接已断开：{}", reason);
            close();
            if (!reconnectStatus) {
                reConnect();
            }
        }

        @Override
        public void onFailure(final WebSocket webSocket, final Throwable t, final Response response) {
            t.printStackTrace();
            close();
            if (!reconnectStatus) {

                reConnect();
            }
        }

//        @Override
//        public void onMessage(final WebSocket webSocket, final ByteString bytes) {
//            final String s = uncompress(bytes.toByteArray());
//            onMessage(webSocket,s);
//        }

        @Override
        public void onMessage(final WebSocket webSocket, final String message) {
            try {
                if (message.equals("pong")) {
                    log.info("保持连接：收到pong响应");
                    return;
                }
                JSONObject jsonObject = JSONObject.parseObject(message);
                if (jsonObject.containsKey("code") && !jsonObject.get("code").toString().equals("0")) {
                    log.error("code not is 0 msg:{}", message);
                    if (Objects.nonNull(builder.errorListener)) {
                        builder.errorListener.onReceive(message);
                    }
                    return;
                }

                if (jsonObject.containsKey("event") && jsonObject.get("event").equals("login")) {
                    log.info("login msg:{}", message);
                    loginStatus = true;
                    return;
                }
                SubscriptionListener listener = null;
                if (jsonObject.containsKey("data")) {
                    listener = getListener(jsonObject);

                    //check sum
                    boolean checkSumFlag = checkSum(jsonObject);
                    if (!checkSumFlag) {
                        return;
                    }

                    if (Objects.nonNull(listener)) {
                        listener.onReceive(message);
                        return;
                    }
                    if (Objects.nonNull(builder.listener)) {
                        builder.listener.onReceive(message);
                        return;
                    }
                }
                log.info("receive op msg:{}", message);
            } catch (Exception e) {
                log.error("receive error msg:{}", message);
            }
        }

        private boolean checkSum(JSONObject jsonObject) {
            try {
                if (!jsonObject.containsKey("arg") || !jsonObject.containsKey("action")) {
                    return true;
                }
                String arg = jsonObject.get("arg").toString();
                String action = jsonObject.get("action").toString();
                SubscribeReq subscribeReq = JSONObject.parseObject(arg, SubscribeReq.class);

                if (!StringUtils.equalsIgnoreCase(subscribeReq.getChannel(), "books")) {
                    return true;
                }
                JSONArray data = (JSONArray) jsonObject.get("data");
                BitgetWsHandle.BookInfo bookInfo = JSONObject.parseObject(JSONObject.toJSONString(data.get(0)), BitgetWsHandle.BookInfo.class);

                if (StringUtils.equalsIgnoreCase(action, "snapshot")) {
                    allBook.put(subscribeReq, bookInfo);
                    return true;
                }
                if (StringUtils.equalsIgnoreCase(action, "update")) {
                    BookInfo all = allBook.get(subscribeReq);
                    boolean checkNum = all.merge(bookInfo).checkSum(Integer.parseInt(bookInfo.getChecksum()), 25);

                    if (!checkNum) {
                        ArrayList<SubscribeReq> subList = new ArrayList<>();
                        subList.add(subscribeReq);
                        this.bitgetWsClient.subscribe(subList);
                    }

                    return checkNum;
                }

            } catch (Exception e) {
                e.printStackTrace();
            }


            return true;
        }

        private SubscriptionListener getListener(JSONObject jsonObject) {
            try {
                if (jsonObject.containsKey("arg")) {
                    SubscribeReq subscribeReq = JSONObject.parseObject(jsonObject.get("arg").toString(), SubscribeReq.class);
                    return scribeMap.get(subscribeReq);
                }
            } catch (Exception e) {

            }
            return null;

        }

        private void close() {
            loginStatus = false;
            connectStatus = false;
            if (webSocket != null) {  // 增加空值判断
                webSocket.close(1000, "Long time no message was sent or received！");
                webSocket = null;
            }
        }

        private void reConnect() {
            reconnectStatus = true;
            log.info("开始重新连接WebSocket服务器...");
            initClient();
            if (CollectionUtils.isNotEmpty(allSuribe)) {
                subscribe(new ArrayList<>(allSuribe));
            }
        }

    }

    public static class BitgetClientBuilder {
        private String pushUrl;
        private boolean isLogin;
        private String apiKey;
        private String secretKey;
        private String passPhrase;

        private SignTypeEnum signType = SignTypeEnum.SHA256;

        private SubscriptionListener listener;
        private SubscriptionListener errorListener;

        private Proxy proxy;

        public BitgetClientBuilder listener(SubscriptionListener listener) {
            this.listener = listener;
            return this;
        }

        public BitgetClientBuilder errorListener(SubscriptionListener errorListener) {
            this.errorListener = errorListener;
            return this;
        }

        public BitgetClientBuilder pushUrl(String pushUrl) {
            this.pushUrl = pushUrl;
            return this;
        }

        public BitgetClientBuilder isLogin(boolean isLogin) {
            this.isLogin = isLogin;
            return this;
        }

        public BitgetClientBuilder apiKey(String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        public BitgetClientBuilder secretKey(String secretKey) {
            this.secretKey = secretKey;
            return this;
        }

        public BitgetClientBuilder passPhrase(String passPhrase) {
            this.passPhrase = passPhrase;
            return this;
        }

        public BitgetClientBuilder signType(SignTypeEnum signType) {
            this.signType = signType;
            return this;
        }

        public BitgetClientBuilder proxy(Proxy proxy) {
            this.proxy = proxy;
            return this;
        }

        /**
         * 设置代理
         * @param type 代理类型
         * @param hostname 主机名
         * @param port 端口号
         * @return
         */
        public BitgetClientBuilder proxy(Proxy.Type type,String hostname, int port) {
            this.proxy = new Proxy(type, new InetSocketAddress(hostname, port));
            return this;
        }

        public BitgetWsClient build() {
            return new BitgetWsHandle(this);
        }

    }

    @Data
    static class BookInfo {
        private List<String[]> asks;
        private List<String[]> bids;
        private String checksum;
        private String ts;

        public BookInfo() {
        }

        public BookInfo merge(BookInfo updateInfo) {
            this.asks = merge(this.asks, updateInfo.getAsks(), false);
            log.info("asks sort uniq:{}", JSONObject.toJSONString(this.asks));
            this.bids = merge(this.bids, updateInfo.getBids(), true);
            log.info("bids sort uniq:{}", JSONObject.toJSONString(this.bids));
            return this;
        }

        //isReverse: true->desc,false->asc
        private List<String[]> merge(List<String[]> allList, List<String[]> updateList, boolean isReverse) {
            Map<String, String[]> priceAndValue = allList.stream().collect(Collectors.toMap(o -> o[0], o -> o));
            for (String[] update : updateList) {
                if (new BigDecimal(update[1]).compareTo(BigDecimal.ZERO) == 0) {
                    priceAndValue.remove(update[0]);
                    continue;
                }
                priceAndValue.put(update[0], update);

            }

            List<String[]> newAllList = new ArrayList<>(priceAndValue.values());
            if (isReverse) {
                newAllList.sort((o1, o2) -> new BigDecimal(o2[0]).compareTo(new BigDecimal(o1[0])));
            } else {
                newAllList.sort(Comparator.comparing(o -> new BigDecimal(o[0])));
            }

            return newAllList;
        }

        public <T> Predicate<T> distinctByKey(Function<? super T, Object> keyExtractor) {
            Map<Object, Boolean> map = new ConcurrentHashMap<>();
            return t -> map.putIfAbsent(keyExtractor.apply(t), Boolean.TRUE) == null;
        }

        public boolean checkSum(int checkSum, int gear) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < gear; i++) {
                if (i < this.getBids().size()) {
                    String[] bids = this.getBids().get(i);
                    sb.append(bids[0]).append(":").append(bids[1]).append(":");
                }

                if (i < this.getAsks().size()) {
                    String[] asks = this.getAsks().get(i);
                    sb.append(asks[0]).append(":").append(asks[1]).append(":");
                }
            }
            String s = sb.toString();
            String str = s.substring(0, s.length() - 1);

            CRC32 crc32 = new CRC32();
            crc32.update(str.getBytes());
            int value = (int) crc32.getValue();
            log.info("check val:{}", str);
            log.info("start checknum mergeVal:{} checkVal:{}", value, checkSum);
            return value == checkSum;
        }
    }
}
