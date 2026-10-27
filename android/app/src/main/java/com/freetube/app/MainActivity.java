
package com.freetube.app;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.DownloadListener;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.Toast;

import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.AdSize;
import com.google.android.gms.ads.AdView;
import com.google.android.gms.ads.MobileAds;

public class MainActivity extends Activity {

    private static final String HOME_URL =
            "https://chawdreegaming.github.io/FreeTube/";

    // Google official test banner ID
    private static final String BANNER_AD_UNIT_ID =
            "ca-app-pub-3940256099942544/9214589741";

    private WebView webView;
    private AdView adView;
    private ValueCallback<Uri[]> fileCallback;

    private static final int FILE_CHOOSER_REQUEST = 1201;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        getWindow().setStatusBarColor(0xFF251D2D);
        getWindow().setNavigationBarColor(0xFF191A20);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF191A20);

        webView = new WebView(this);
        webView.setBackgroundColor(0xFF191A20);

        root.addView(webView, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        FrameLayout adContainer = new FrameLayout(this);
        adContainer.setBackgroundColor(Color.WHITE);

        root.addView(adContainer, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));

        setContentView(root);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(true);
        settings.setLoadsImagesAutomatically(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(true);
        settings.setMixedContentMode(
                WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setMediaPlaybackRequiresUserGesture(true);

        CookieManager cookies = CookieManager.getInstance();
        cookies.setAcceptCookie(true);
        cookies.setAcceptThirdPartyCookies(webView, false);

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
                            FILE_CHOOSER_REQUEST);
                    return true;
                } catch (ActivityNotFoundException e) {
                    fileCallback = null;
                    Toast.makeText(
                            MainActivity.this,
                            "No file picker is available.",
                            Toast.LENGTH_LONG).show();
                    return false;
                }
            }
        });

        webView.setDownloadListener(new DownloadListener() {
            @Override
            public void onDownloadStart(
                    String url, String userAgent,
                    String contentDisposition, String mimetype,
                    long contentLength) {
                try {
                    startActivity(new Intent(
                            Intent.ACTION_VIEW, Uri.parse(url)));
                } catch (Exception e) {
                    Toast.makeText(
                            MainActivity.this,
                            "Unable to open this download.",
                            Toast.LENGTH_SHORT).show();
                }
            }
        });

        if (savedInstanceState != null) {
            webView.restoreState(savedInstanceState);
        } else {
            webView.loadUrl(HOME_URL);
        }

        MobileAds.initialize(this, initializationStatus -> {
            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()
                        || adContainer.getParent() == null) {
                    return;
                }

                adView = new AdView(MainActivity.this);
                adView.setAdUnitId(BANNER_AD_UNIT_ID);

                int widthPixels = getResources()
                        .getDisplayMetrics().widthPixels;
                float density = getResources()
                        .getDisplayMetrics().density;
                int adWidth = (int) (widthPixels / density);

                adView.setAdSize(
                        AdSize.getCurrentOrientationAnchoredAdaptiveBannerAdSize(
                                MainActivity.this, adWidth));

                adContainer.addView(adView);

                AdRequest request = new AdRequest.Builder().build();
                adView.loadAd(request);
            });
        });
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
                        Toast.LENGTH_SHORT).show();
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

        if (adView != null) {
            adView.destroy();
            adView = null;
        }

        if (webView != null) {
            webView.stopLoading();
            webView.destroy();
            webView = null;
        }

        super.onDestroy();
    }
}
