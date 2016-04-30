/*
 * Copyright (c) 2015 GDG VIT Vellore.
 * This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.sumatone.cloud.securecloud.Activities;

import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.sumatone.cloud.securecloud.Fragments.DownloadFragment;
import com.sumatone.cloud.securecloud.Fragments.UploadFragment;
import com.sumatone.cloud.securecloud.R;
import com.sumatone.cloud.securecloud.Customs.SlidingTabLayout;


/**
 * Created by shalini on 16-06-2015.
 */
public class MainActivity extends AppCompatActivity implements ViewPager.OnPageChangeListener {


    private static final int NUM_PAGES = 2;
    private ViewPager pager;
    private SliderAdapter adapter;
    private SlidingTabLayout tabs;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        init();
        setInit();
        setData();
    }

    private void init() {
        adapter = new SliderAdapter(getSupportFragmentManager());
        pager = (ViewPager) findViewById(R.id.pager);
        tabs = (SlidingTabLayout) findViewById(R.id.tabs);

    }

    private void setInit() {
        tabs.setDistributeEvenly(true); // To make the Tabs Fixed set this true, This makes the tabs Space Evenly in Available width
        // Setting Custom Color for the Scroll bar indicator of the Tab View
        tabs.setCustomTabColorizer(new SlidingTabLayout.TabColorizer() {
            @Override
            public int getIndicatorColor(int position) {
                return getResources().getColor(R.color.white);
            }
        });
        pager.addOnPageChangeListener(this);


    }


    public void setData() {
        pager.setAdapter(adapter);
        tabs.setViewPager(pager);
    }


    @Override
    public void onResume() {
        super.onResume();
    }

    @Override
    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {

    }

    @Override
    public void onPageSelected(int position) {
        if(position==1) {
            ((DownloadFragment)adapter.getFragment()).setData();
        }
    }

    @Override
    public void onPageScrollStateChanged(int state) {

    }


    private class SliderAdapter extends FragmentStatePagerAdapter {
        String[] tabs;
        Fragment f;
        public SliderAdapter(FragmentManager supportFragmentManager) {
            super(supportFragmentManager);
            tabs = getResources().getStringArray(R.array.tabs_name);
        }

        @Override
        public Fragment getItem(int position) {
            Log.d("pos", String.valueOf(position));

            if (position == 0)
                f = new UploadFragment();
            else
                f = new DownloadFragment();

            return f;

        }

        public Fragment getFragment(){
            return f;
        }

        @Override
        public CharSequence getPageTitle(int position) {
            return tabs[position];
        }

        @Override

        public int getCount() {
            return NUM_PAGES;
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        Log.d("called", String.valueOf(requestCode));
    }
}
