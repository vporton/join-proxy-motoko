import Call "canister:call";
import Blob "mo:core/Blob";
import Text "mo:core/Text";
import Runtime "mo:core/Runtime";

persistent actor Test {
    public shared func test(path: Text, arg: Text, body: Text, port: Text, port2: Text)
        : async (Text, [{name: Text; value: Text}])
    {
        // Remark: As test_port_443 test shows, port is included in default Host: iff it is included in the URL.
        let headers = [ // Header names must be lowercase.
            ("host", ["local.vporton.name" # port2]),
            ("content-type", ["text/plain"]),
            ("x-my", ["my"]),
        ];
        let res = await Call.callHttp(
            {
                url = "https://local.vporton.name" # port # path # "?arg=" # arg;
                headers;
                body = Text.encodeUtf8(body);
                method = #post;
            },
            {
                max_response_bytes = ?10_000;
                cycles = 1_000_000_000;
                timeout = 60_000_000_000; // 60 sec
            },
        );
        let ?resp_body = Text.decodeUtf8(Blob.fromArray(res.body)) else {
            Runtime.trap("can't decode response body.")
        };
        if (res.status != 200) {
            Runtime.trap("invalid response from proxy: " # resp_body);
        };
        (resp_body, res.headers);
    };
};