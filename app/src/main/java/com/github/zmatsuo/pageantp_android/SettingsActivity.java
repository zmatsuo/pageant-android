
package com.github.zmatsuo.pageantp_android;

import android.os.Bundle;
import android.preference.PreferenceActivity;
import android.preference.PreferenceFragment;
import android.view.View;

public class SettingsActivity extends PreferenceActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        getFragmentManager().beginTransaction()
            .replace(android.R.id.content, new MainPreferenceFragment())
            .commit();
    }

    /********** PreferenceFragment **********/

    public static class MainPreferenceFragment extends PreferenceFragment {

        public MainPreferenceFragment() {
            // Required empty public constructor
        }

        @Override
        public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            addPreferencesFromResource(R.xml.preferences);
        }

        @Override
        public void onViewCreated(View view, Bundle savedInstanceState) {
            super.onViewCreated(view, savedInstanceState);
        }
    }
}
