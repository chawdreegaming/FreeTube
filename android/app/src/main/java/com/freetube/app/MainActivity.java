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

    private final Map<String, Integer> loadVersions =
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

        // Native ads overlay the HTML ad slots.
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
                    WebView view,
                    String url,
                    android.graphics.Bitmap favicon) {
                clearNativeAds();
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                if (!isDiscoveryPage(url)) {
                    clearNativeAds();
                } else {
                    refreshSlotPositions();
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
            // WebView state restored.
        } else {
            webView.loadUrl(HOME_URL);
        }

        MobileAds.initialize(this, status ->
                runOnUiThread(() -> {
                    adsInitialized = true;
                    refreshSlotPositions();
                })
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

            if (slotId == null || slotId.trim().isEmpty()) {
                return;
            }

            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()
                        || webView == null
                        || !isDiscoveryPage(webView.getUrl())) {
                    return;
                }

                NativeAdView existing = adViews.get(slotId);

                if (!visible || width <= 0 || height <= 0) {
                    if (existing != null) {
                        existing.setVisibility(View.GONE);
                    }
                    return;
                }

                if (existing == null) {
                    loadNativeAd(slotId);
                    return;
                }

                positionAd(existing, x, y, width, height);
            });
        }
    }

    private void loadNativeAd(String slotId) {
        if (!adsInitialized
                || loadingAds.containsKey(slotId)
                || nativeAds.containsKey(slotId)
                || isFinishing()
                || isDestroyed()) {
            return;
        }

        final int version =
                loadVersions.containsKey(slotId)
                        ? loadVersions.get(slotId) : 0;

        AdLoader loader = new AdLoader.Builder(
                this, NATIVE_AD_UNIT_ID
        )
                .forNativeAd(nativeAd -> runOnUiThread(() -> {

                    loadingAds.remove(slotId);

                    Integer currentVersion = loadVersions.get(slotId);

                    if (isFinishing() || isDestroyed()
                            || webView == null
                            || !isDiscoveryPage(webView.getUrl())
                            || currentVersion == null
                            || currentVersion != version) {
                        nativeAd.destroy();
                        return;
                    }

                    NativeAd oldAd = nativeAds.put(slotId, nativeAd);
                    if (oldAd != null) {
                        oldAd.destroy();
                    }

                    NativeAdView nativeAdView =
                            createNativeAdView(nativeAd);

                    NativeAdView previous =
                            adViews.put(slotId, nativeAdView);

                    if (previous != null) {
                        adOverlay.removeView(previous);
                    }

                    adOverlay.addView(nativeAdView);

                    refreshSlotPositions();
                }))
                .withAdListener(new AdListener() {
                    @Override
                    public void onAdFailedToLoad(LoadAdError error) {
                        loadingAds.remove(slotId);

                        android.util.Log.w(
                                "FreeTubeAds",
                                "Native ad failed for " + slotId
                                        + ": " + error.getMessage()
                        );
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

        // Sponsored label
        TextView sponsored = new TextView(this);
        sponsored.setText("Ad · Sponsored");
        sponsored.setTextColor(Color.rgb(40, 100, 65));
        sponsored.setTextSize(11);
        sponsored.setTypeface(null, Typeface.BOLD);
        card.addView(sponsored);

        // Headline
        TextView headline = new TextView(this);
        headline.setTextColor(Color.rgb(25, 35, 28));
        headline.setTextSize(16);
        headline.setTypeface(null, Typeface.BOLD);
        headline.setPadding(0, dp(5), 0, dp(5));
        card.addView(headline);

        adView.setHeadlineView(headline);

        // Advertiser
        TextView advertiser = new TextView(this);
        advertiser.setTextColor(Color.DKGRAY);
        advertiser.setTextSize(12);
        card.addView(advertiser);

        adView.setAdvertiserView(advertiser);

        // MediaView must be large enough for video creatives.
        MediaView mediaView = new MediaView(this);
        mediaView.setMinimumWidth(dp(120));
        mediaView.setMinimumHeight(dp(120));

        LinearLayout.LayoutParams mediaParams =
                new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        dp(160)
                );

        mediaParams.setMargins(0, dp(8), 0, dp(8));
        card.addView(mediaView, mediaParams);
        adView.setMediaView(mediaView);

        // Body text
        TextView body = new TextView(this);
        body.setTextColor(Color.DKGRAY);
        body.setTextSize(13);
        card.addView(body);
        adView.setBodyView(body);

        // Icon and call-to-action
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

        adView.addView(card, new NativeAdView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        // Populate assets from the loaded ad.
        headline.setText(ad.getHeadline() == null
                ? "Sponsored" : ad.getHeadline());

        String advertiserText = ad.getAdvertiser();
        advertiser.setText(advertiserText == null
                ? "" : advertiserText);
        advertiser.setVisibility(
                advertiserText == null || advertiserText.isEmpty()
                        ? View.GONE : View.VISIBLE
        );

        String bodyText = ad.getBody();
        body.setText(bodyText == null ? "" : bodyText);
        body.setVisibility(
                bodyText == null || bodyText.isEmpty()
                        ? View.GONE : View.VISIBLE
        );

        String ctaText = ad.getCallToAction();
        cta.setText(ctaText == null ? "Learn more" : ctaText);
        cta.setVisibility(
                ctaText == null || ctaText.isEmpty()
                        ? View.GONE : View.VISIBLE
        );

        if (ad.getIcon() != null) {
            icon.setImageDrawable(ad.getIcon().getDrawable());
            icon.setVisibility(View.VISIBLE);
        } else {
            icon.setVisibility(View.GONE);
        }

        // Register the native assets only after assigning their views.
        adView.setNativeAd(ad);

        return adView;
    }

    /*
     * The JavaScript rect is relative to the WebView viewport.
     * Convert its position into coordinates relative to the overlay.
     * Do not add WebView scrollY: getBoundingClientRect() already
     * accounts for scrolling.
     */
    private void positionAd(
            NativeAdView view,
            double x,
            double y,
            double width,
            double height) {

        if (root == null || webView == null) return;

        float density = getResources()
                .getDisplayMetrics().density;

        int[] webLocation = new int[2];
        int[] rootLocation = new int[2];

        webView.getLocationInWindow(webLocation);
        root.getLocationInWindow(rootLocation);

        int left = webLocation[0] - rootLocation[0]
                + (int) Math.round(x * density);

        int top = webLocation[1] - rootLocation[1]
                + (int) Math.round(y * density);

        int widthPx = Math.max(
                dp(120), (int) Math.round(width * density)
        );

        int heightPx = Math.max(
                dp(120), (int) Math.round(height * density)
        );

        FrameLayout.LayoutParams params =
                new FrameLayout.LayoutParams(widthPx, heightPx);

        params.leftMargin = left;
        params.topMargin = top;
        params.gravity = Gravity.TOP | Gravity.LEFT;

        view.setVisibility(View.VISIBLE);
        view.setLayoutParams(params);
    }

    private void refreshSlotPositions() {
        if (webView == null || !adsInitialized) return;

        runOnUiThread(() -> {
            if (webView != null
                    && isDiscoveryPage(webView.getUrl())) {
                webView.evaluateJavascript(
                        "if (window.updateNativeAdSlots) "
                                + "window.updateNativeAdSlots();",
                        null
                );
            }
        });
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
            if (adOverlay != null) {
                adOverlay.removeView(view);
            }
        }
        adViews.clear();

        for (NativeAd ad : nativeAds.values()) {
            ad.destroy();
        }
        nativeAds.clear();

        for (String slotId : loadingAds.keySet()) {
            Integer version = loadVersions.get(slotId);
            loadVersions.put(
                    slotId, version == null ? 1 : version + 1
            );
        }
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

        if (scheme.equals("http")
                || scheme.equals("https")
                || scheme.equals("mailto")
                || scheme.equals("tel")) {
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, uri));
            } catch (Exception e) {
                Toast.makeText(
                        this,
                        "No app can open this link.",
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
        if (webView != null) {
            webView.saveState(outState);
        }
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