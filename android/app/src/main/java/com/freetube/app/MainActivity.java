package com.freetube.app;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.DownloadListener;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.gms.ads.AdListener;
import com.google.android.gms.ads.AdLoader;
import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.LoadAdError;
import com.google.android.gms.ads.MobileAds;
import com.google.android.gms.ads.nativead.MediaView;
import com.google.android.gms.ads.nativead.NativeAd;
import com.google.android.gms.ads.nativead.NativeAdOptions;
import com.google.android.gms.ads.nativead.NativeAdView;

import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

public class MainActivity extends Activity {

    private static final String HOME_URL =
            "https://chawdreegaming.github.io/FreeTube/";

    // Google's official TEST Native Ad Unit ID.
    private static final String NATIVE_AD_UNIT_ID =
            "ca-app-pub-3940256099942544/2247696110";

    private static final int FILE_CHOOSER_REQUEST = 1201;

    private FrameLayout root;
    private WebView webView;
    private FrameLayout adOverlay;
    private ValueCallback<Uri[]> fileCallback;

    private boolean adsInitialized = false;

    private final Map<String, NativeAdView> adViews =
            new HashMap<>();

    private final Map<String, NativeAd> nativeAds =
            new HashMap<>();

    private final Map<String, AdLoader> loadingAds =
            new HashMap<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        getWindow().setStatusBarColor(0xFF251D2D);
        getWindow().setNavigationBarColor(0xFF191A20);

        root = new FrameLayout(this);
        root.setBackgroundColor(0xFF191A20);

        webView = new WebView(this);
        webView.setBackgroundColor(0xFF191A20);

        root.addView(webView, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));

        // Transparent overlay: Native ads will be positioned
        // over the HTML ad slots, not at the bottom of the app.
        adOverlay = new FrameLayout(this);
        adOverlay.setClipChildren(false);
        adOverlay.setClipToPadding(false);

        root.addView(adOverlay, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
        ));

        setContentView(root);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setLoadsImagesAutomatically(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(true);
        settings.setMixedContentMode(
                WebSettings.MIXED_CONTENT_NEVER_ALLOW
        );

        // Allow muted autoplay in the WebView.
        settings.setMediaPlaybackRequiresUserGesture(false);

        CookieManager cookies = CookieManager.getInstance();
        cookies.setAcceptCookie(true);
        cookies.setAcceptThirdPartyCookies(webView, false);

        webView.addJavascriptInterface(
                new NativeAdBridge(), "FreeTubeAds"
        );

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(
                    WebView view, WebResourceRequest request) {
                return openUrl(request.getUrl());
            }

            @Override
            public boolean shouldOverrideUrlLoading(
                    WebView view, String url) {
                return openUrl(Uri.parse(url));
            }

            @Override
            public void onPageStarted(
                    WebView view, String url, android.graphics.Bitmap favicon) {
                clearNativeAds();
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                if (!isDiscoveryPage(url)) {
                    clearNativeAds();
                }
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(
                    WebView view,
                    ValueCallback<Uri[]> callback,
                    FileChooserParams params) {

                if (fileCallback != null) {
                    fileCallback.onReceiveValue(null);
                }

                fileCallback = callback;

                try {
                    startActivityForResult(
                            params.createIntent(),
                            FILE_CHOOSER_REQUEST
                    );
                    return true;
                } catch (ActivityNotFoundException e) {
                    fileCallback = null;
                    Toast.makeText(
                            MainActivity.this,
                            "No file picker is available.",
                            Toast.LENGTH_LONG
                    ).show();
                    return false;
                }
            }
        });

        webView.setDownloadListener(
                (url, userAgent, contentDisposition,
                 mimetype, contentLength) -> {
                    try {
                        startActivity(new Intent(
                                Intent.ACTION_VIEW, Uri.parse(url)
                        ));
                    } catch (Exception e) {
                        Toast.makeText(
                                MainActivity.this,
                                "Unable to open this download.",
                                Toast.LENGTH_SHORT
                        ).show();
                    }
                }
        );

        if (savedInstanceState != null
                && webView.restoreState(savedInstanceState) != null) {
            // Existing WebView state restored.
        } else {
            webView.loadUrl(HOME_URL);
        }

        MobileAds.initialize(this, status ->
                runOnUiThread(() -> adsInitialized = true)
        );
    }

    private boolean isDiscoveryPage(String url) {
        if (url == null) return false;

        Uri uri = Uri.parse(url);
        String host = uri.getHost() == null
                ? "" : uri.getHost().toLowerCase();

        String path = uri.getPath() == null
                ? "" : uri.getPath().toLowerCase();

        return host.equals("chawdreegaming.github.io")
                && path.endsWith("/discover.html");
    }

    private class NativeAdBridge {

        @JavascriptInterface
        public void updateSlot(
                String slotId,
                double x,
                double y,
                double width,
                double height,
                boolean visible) {

            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()
                        || webView == null
                        || !isDiscoveryPage(webView.getUrl())) {
                    return;
                }

                if (!visible || width <= 0 || height <= 0) {
                    NativeAdView existing = adViews.get(slotId);
                    if (existing != null) {
                        existing.setVisibility(View.GONE);
                    }
                    return;
                }

                NativeAdView existing = adViews.get(slotId);

                if (existing == null) {
                    loadNativeAd(slotId);
                    return;
                }

                positionAd(existing, x, y, width, height);
            });
        }
    }

    private void loadNativeAd(String slotId) {
        if (!adsInitialized || loadingAds.containsKey(slotId)
                || nativeAds.containsKey(slotId)) {
            return;
        }

        AdLoader loader = new AdLoader.Builder(
                this, NATIVE_AD_UNIT_ID
        )
                .forNativeAd(nativeAd -> runOnUiThread(() -> {
                    loadingAds.remove(slotId);

                    if (isFinishing() || isDestroyed()
                            || webView == null
                            || !isDiscoveryPage(webView.getUrl())) {
                        nativeAd.destroy();
                        return;
                    }

                    NativeAd old = nativeAds.put(slotId, nativeAd);
                    if (old != null) old.destroy();

                    NativeAdView nativeAdView =
                            createNativeAdView(nativeAd);

                    NativeAdView previous = adViews.put(
                            slotId, nativeAdView
                    );

                    if (previous != null) {
                        adOverlay.removeView(previous);
                    }

                    adOverlay.addView(nativeAdView);

                    // Ask the page to send the slot's current
                    // position after the ad has loaded.
                    webView.evaluateJavascript(
                            "window.updateNativeAdSlots"
                                    + " && window.updateNativeAdSlots();",
                            null
                    );
                }))
                .withAdListener(new AdListener() {
                    @Override
                    public void onAdFailedToLoad(LoadAdError error) {
                        loadingAds.remove(slotId);
                    }
                })
                .withNativeAdOptions(
                        new NativeAdOptions.Builder().build()
                )
                .build();

        loadingAds.put(slotId, loader);
        loader.loadAd(new AdRequest.Builder().build());
    }

    private NativeAdView createNativeAdView(NativeAd ad) {
        NativeAdView adView = new NativeAdView(this);
        adView.setBackground(makeBackground(
                Color.WHITE, 0xFFE0E0E0
        ));

        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(12), dp(10), dp(12), dp(10));

        TextView sponsored = new TextView(this);
        sponsored.setText("Ad · Sponsored");
        sponsored.setTextColor(Color.rgb(40, 100, 65));
        sponsored.setTextSize(11);
        sponsored.setTypeface(null, Typeface.BOLD);
        card.addView(sponsored);

        TextView headline = new TextView(this);
        headline.setTextColor(Color.rgb(25, 35, 28));
        headline.setTextSize(16);
        headline.setTypeface(null, Typeface.BOLD);
        headline.setPadding(0, dp(5), 0, dp(5));
        card.addView(headline);

        adView.setHeadlineView(headline);

        TextView advertiser = new TextView(this);
        advertiser.setTextColor(Color.DKGRAY);
        advertiser.setTextSize(12);
        card.addView(advertiser);
        adView.setAdvertiserView(advertiser);

        MediaView mediaView = new MediaView(this);
        LinearLayout.LayoutParams mediaParams =
                new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        dp(100)
                );
        mediaParams.setMargins(0, dp(8), 0, dp(8));
        card.addView(mediaView, mediaParams);
        adView.setMediaView(mediaView);

        TextView body = new TextView(this);
        body.setTextColor(Color.DKGRAY);
        body.setTextSize(13);
        card.addView(body);
        adView.setBodyView(body);

        LinearLayout bottom = new LinearLayout(this);
        bottom.setGravity(Gravity.CENTER_VERTICAL);
        bottom.setOrientation(LinearLayout.HORIZONTAL);

        ImageView icon = new ImageView(this);
        icon.setScaleType(ImageView.ScaleType.FIT_CENTER);
        LinearLayout.LayoutParams iconParams =
                new LinearLayout.LayoutParams(dp(38), dp(38));
        iconParams.setMargins(0, dp(8), dp(10), 0);
        bottom.addView(icon, iconParams);
        adView.setIconView(icon);

        Button cta = new Button(this);
        cta.setTextSize(12);
        cta.setAllCaps(false);
        bottom.addView(cta, new LinearLayout.LayoutParams(
                0, dp(44), 1
        ));
        adView.setCallToActionView(cta);

        card.addView(bottom);
        adView.addView(card);

        headline.setText(ad.getHeadline() == null
                ? "Sponsored" : ad.getHeadline());

        advertiser.setText(ad.getAdvertiser() == null
                ? "" : ad.getAdvertiser());

        body.setText(ad.getBody() == null ? "" : ad.getBody());
        body.setVisibility(ad.getBody() == null
                ? View.GONE : View.VISIBLE);

        cta.setText(ad.getCallToAction() == null
                ? "Learn more" : ad.getCallToAction());
        cta.setVisibility(ad.getCallToAction() == null
                ? View.GONE : View.VISIBLE);

        if (ad.getIcon() != null) {
            icon.setImageDrawable(ad.getIcon().getDrawable());
            icon.setVisibility(View.VISIBLE);
        } else {
            icon.setVisibility(View.GONE);
        }

        adView.setNativeAd(ad);

        return adView;
    }

    private void positionAd(
            NativeAdView view,
            double x,
            double y,
            double width,
            double height) {

        float density = getResources()
                .getDisplayMetrics().density;

        FrameLayout.LayoutParams params =
                new FrameLayout.LayoutParams(
                        Math.max(1, (int) (width * density)),
                        Math.max(1, (int) (height * density))
                );

        params.leftMargin = (int) (x * density);
        params.topMargin = (int) (y * density);

        view.setVisibility(View.VISIBLE);
        view.setLayoutParams(params);
    }

    private GradientDrawable makeBackground(
            int fillColor, int strokeColor) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fillColor);
        drawable.setCornerRadius(dp(10));
        drawable.setStroke(dp(1), strokeColor);
        return drawable;
    }

    private int dp(int value) {
        return (int) (value * getResources()
                .getDisplayMetrics().density + 0.5f);
    }

    private void clearNativeAds() {
        for (NativeAdView view : adViews.values()) {
            adOverlay.removeView(view);
        }
        adViews.clear();

        for (NativeAd ad : nativeAds.values()) {
            ad.destroy();
        }
        nativeAds.clear();
        loadingAds.clear();
    }

    private boolean openUrl(Uri uri) {
        if (uri == null) return true;

        String scheme = uri.getScheme() == null
                ? "" : uri.getScheme().toLowerCase();

        String host = uri.getHost() == null
                ? "" : uri.getHost().toLowerCase();

        boolean allowedHost =
                host.equals("chawdreegaming.github.io")
                || host.equals("freetube-backend-a222.onrender.com");

        if (scheme.equals("https") && allowedHost) {
            return false;
        }

        if (scheme.equals("http") || scheme.equals("https")
                || scheme.equals("mailto") || scheme.equals("tel")) {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, uri));
            } catch (Exception e) {
                Toast.makeText(
                        this, "No app can open this link.",
                        Toast.LENGTH_SHORT
                ).show();
            }
        }

        return true;
    }

    @Override
    protected void onActivityResult(
            int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == FILE_CHOOSER_REQUEST
                && fileCallback != null) {
            Uri[] results = null;

            if (resultCode == Activity.RESULT_OK && data != null) {
                Uri selected = data.getData();

                if (selected != null) {
                    results = new Uri[]{selected};
                } else if (data.getClipData() != null) {
                    int count = data.getClipData().getItemCount();
                    results = new Uri[count];

                    for (int i = 0; i < count; i++) {
                        results[i] = data.getClipData()
                                .getItemAt(i).getUri();
                    }
                }
            }

            fileCallback.onReceiveValue(results);
            fileCallback = null;
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        if (webView != null) webView.saveState(outState);
        super.onSaveInstanceState(outState);
    }

    @Override
    protected void onDestroy() {
        if (fileCallback != null) {
            fileCallback.onReceiveValue(null);
            fileCallback = null;
        }

        clearNativeAds();

        if (webView != null) {
            webView.stopLoading();
            webView.removeJavascriptInterface("FreeTubeAds");
            webView.destroy();
            webView = null;
        }

        super.onDestroy();
    }
}
