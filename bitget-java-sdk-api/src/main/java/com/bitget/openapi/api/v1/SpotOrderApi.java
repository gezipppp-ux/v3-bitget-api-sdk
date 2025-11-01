package com.bitget.openapi.api.v1;

import com.bitget.openapi.dto.response.ResponseResult;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.POST;

import java.util.Map;

public interface SpotOrderApi {

    // order
    @POST("/api/spot/v1/trade/orders")
    Call<ResponseResult> orders(@Body Map<String, Object> body);

    @POST("/api/spot/v1/trade/batch-orders")
    Call<ResponseResult> batchOrders(@Body Map<String, Object> body);

    @POST("/api/spot/v1/trade/cancel-order")
    Call<ResponseResult> cancelOrder(@Body Map<String, Object> body);

    @POST("/api/spot/v1/trade/cancel-batch-orders")
    Call<ResponseResult> cancelBatchOrder(@Body Map<String, Object> body);

    @POST("/api/spot/v1/trade/open-orders")
    Call<ResponseResult> openOrders(@Body Map<String, Object> body);

    @POST("/api/spot/v1/trade/history")
    Call<ResponseResult> history(@Body Map<String, Object> body);

    @POST("/api/spot/v1/trade/fills")
    Call<ResponseResult> fills(@Body Map<String, Object> body);


    // plan
    @POST("/api/spot/v1/plan/placePlan")
    Call<ResponseResult> placePlan(@Body Map<String, Object> body);

    @POST("/api/spot/v1/plan/cancelPlan")
    Call<ResponseResult> cancelPlan(@Body Map<String, Object> body);

    @POST("/api/spot/v1/plan/currentPlan")
    Call<ResponseResult> currentPlan(@Body Map<String, Object> body);

    @POST("/api/spot/v1/plan/historyPlan")
    Call<ResponseResult> historyPlan(@Body Map<String, Object> body);


    // trace
    @POST("/api/spot/v1/trace/order/closeTrackingOrder")
    Call<ResponseResult> traderCloseTrackingOrder(@Body Map<String, Object> body);

    @POST("/api/spot/v1/trace/order/orderCurrentList")
    Call<ResponseResult> traderOrderCurrentList(@Body Map<String, Object> body);

    @POST("/api/spot/v1/trace/order/orderHistoryList")
    Call<ResponseResult> traderOrderHistoryList(@Body Map<String, Object> body);
}
