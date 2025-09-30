import Http "../src";
import Types "../src/HttpTypes";
import Blob "mo:core/Blob";
import Iter "mo:core/Iter";
import Runtime "mo:core/Runtime";

persistent actor HttpCaller {
    let requestsChecker = Http.newHttpRequestsChecker();

    public shared func callHttp(
        request: Http.SharedWrappedHttpRequest,
        params: {cycles: Nat; timeout: Nat; max_response_bytes: ?Nat64},
    ): async Types.HttpResponsePayload {
        await* Http.checkedHttpRequestWrapped(requestsChecker, request, ?{ function = transform; context = "" }, params);
    };

    /// This function is needed even, if you use `inspect`, because
    /// `inspect` is basically a query call and query calls can be forged by a malicious replica.
    public shared func checkRequest(hash: Blob): async () {
        if (not Http.checkHttpRequest(requestsChecker, hash)) {
            Runtime.trap("hacked or timed out HTTP request");
        }
    };

    public query func transform(args: Types.TransformArgs): async Types.HttpResponsePayload {
        let headers = Iter.toArray(Iter.filter(
            args.response.headers.vals(), func (h: {name: Text; value: Text}): Bool {h.name != "date"}
        ));
        {
            status = args.response.status;
            headers;
            body = args.response.body;
        };
    };

    system func inspect({
        // caller : Principal;
        // arg : Blob;
        msg : {
            #callHttp : () ->
                (Http.SharedWrappedHttpRequest,
                {cycles : Nat; max_response_bytes : ?Nat64; timeout : Nat});
            #checkRequest : () -> Blob;
            #transform : () -> Types.TransformArgs
        }
    }) : Bool {
        switch (msg) {
            case (#checkRequest hash) {
                Http.checkHttpRequest(requestsChecker, hash());
            };
            case _ {
                // Should here check permissions:
                true;
            }
        };
    };
}