package com.bitget.openapi.service.v2.mix;

import com.bitget.openapi.api.v2.MixOrderApi;
import com.bitget.openapi.common.client.ApiClient;
import com.bitget.openapi.common.utils.ResponseUtils;
import com.bitget.openapi.dto.response.ResponseResult;

import java.io.IOException;
import java.util.Map;

public class MixOrderService {

    private final MixOrderApi mixOrderApi;

    public MixOrderService(ApiClient client) {
        mixOrderApi = client.create(MixOrderApi.class);
    }

    public ResponseResult placeOrder(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.placeOrder(paramMap).execute().body());
    }

    public ResponseResult batchPlaceOrder(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.batchPlaceOrder(paramMap).execute().body());
    }

    public ResponseResult cancelOrder(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.cancelOrder(paramMap).execute().body());
    }

    public ResponseResult batchCancelOrders(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.batchCancelOrders(paramMap).execute().body());
    }

    public ResponseResult ordersHistory(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.ordersHistory(paramMap).execute().body());
    }

    public ResponseResult ordersPending(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.ordersPending(paramMap).execute().body());
    }

    public ResponseResult fills(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.fills(paramMap).execute().body());
    }

    public ResponseResult placeTPSLOrder(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.placeTPSLOrder(paramMap).execute().body());
    }

    public ResponseResult placePosTPSLOrder(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.placePosTPSLOrder(paramMap).execute().body());
    }



    public ResponseResult placePlanOrder(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.placePlanOrder(paramMap).execute().body());
    }

    public ResponseResult cancelPlanOrder(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.cancelPlanOrder(paramMap).execute().body());
    }

    public ResponseResult ordersPlanPending(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.ordersPlanPending(paramMap).execute().body());
    }

    public ResponseResult ordersPlanHistory(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.ordersPlanHistory(paramMap).execute().body());
    }



    public ResponseResult traderOrderClosePositions(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.traderOrderClosePositions(paramMap).execute().body());
    }

    public ResponseResult traderOrderCurrentTrack(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.traderOrderCurrentTrack(paramMap).execute().body());
    }

    public ResponseResult traderOrderHistoryTrack(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.traderOrderHistoryTrack(paramMap).execute().body());
    }

    public ResponseResult followerClosePositions(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.followerClosePositions(paramMap).execute().body());
    }

    public ResponseResult followerQueryCurrentOrders(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.followerQueryCurrentOrders(paramMap).execute().body());
    }

    public ResponseResult followerQueryHistoryOrders(Map<String, Object> paramMap) throws IOException {
        return ResponseUtils.handleResponse(mixOrderApi.followerQueryHistoryOrders(paramMap).execute().body());
    }

}
