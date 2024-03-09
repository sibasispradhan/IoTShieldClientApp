import streamlit as st
import base64
import pyshark
import os
import requests
import time
import multiprocessing
from datetime import datetime
import subprocess
import platform

from dotenv import load_dotenv
load_dotenv() ## load all the env valriable

import pandas as pd
#from streamlit_extras.stylable_container import stylable_container

# ------ Custom Libraries -------
import pyshark_test
import utils

st.set_page_config(
    page_title="IoTShield App",
    page_icon= os.path.join("wallpaper","favicon.ico"),
    layout="wide",
    initial_sidebar_state="collapsed",  # ("auto", "expanded", or "collapsed")
    menu_items={
        'About': "Author: Sibasis Pradhan"
    }
)

def get_base64(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()

def set_background(png_file):
    bin_str = get_base64(png_file)
    page_bg_img = '''
    <style>
    .stApp {
    background-image: url("data:image/png;base64,%s");
    background-repeat: np-repeat;
    background-size: cover;
    }
    </style>
    ''' % bin_str
    st.markdown(page_bg_img, unsafe_allow_html=True)
    return

set_background(os.path.join("wallpaper","bg_01.png"))

title = 'IoTShield: Attack Detection in IoT & IIoT Device Networks Using ML Model'
style = (
    "color: white; "
    "background-color: rgba(0, 0, 0, 0.0); "
    "font-size: 64px; "
    "text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5); "
    "text-align: center;"
)
st.markdown(f"<h1 style='{style}'>{title}</h1>", unsafe_allow_html=True)

st.divider()

col_widths = [4,2,2,4]
col1, col2, col3, col4 = st.columns(col_widths)
col5, col6, col7, col8 = st.columns(col_widths)
# col10, col11 = st.columns([10,10])

attack_cnt_container = st.empty()

df_container = st.empty()

if 'attack_cnt' not in st.session_state:
    st.session_state['attack_cnt'] = 0

if 'user_email' not in st.session_state:
    st.session_state['user_email'] = '2021sc04667@wilp.bits-pilani.ac.in'

def open_folder(path):
    os.startfile(path)

def download_files_from_github():
    
    repo_owner = os.getenv("GITHUB_USERNAME")
    repo_name = 'IoTShieldApp'
    branch_name = 'main'
    files_to_download = ['artifacts/model.pkl', 'artifacts/preprocessor.pkl', 'artifacts/model2.pkl', 'artifacts/preprocessor2.pkl']
    github_token = os.getenv("GITHUB_ACCESS_TOKEN")

    with st.spinner("Updating IoTShield System Definitions..."):
        for file_to_download in files_to_download:
            download_url = f'https://raw.githubusercontent.com/{repo_owner}/{repo_name}/{branch_name}/{file_to_download}'
            local_file_path = file_to_download
            headers = {"Authorization": f"token {github_token}"}
            response = requests.get(download_url, headers=headers)
            if response.status_code == 200:
                with open(local_file_path, 'wb') as f:
                    f.write(response.content)
                print(f"File downloaded successfully: {local_file_path}")
            else:
                print(f"Failed to download file: {download_url}. Status code: {response.status_code}")

    success = st.success("Done!")
    time.sleep(1)
    success.empty()

with st.sidebar:
    st.markdown("<h2 style='text-align: center; color: black;'>Live Network Packet Capture</h2>", unsafe_allow_html=True)
    st.session_state['run_duration'] = st.slider("🕓 Select duration (min) for pyshark network data streaming:",1.0,100.0,1.0,step=1.0)

    st.divider()
    st.markdown("<h3 style='text-align: center; color: black;'>Update System Definitions:</h3>", unsafe_allow_html=True)
    if st.button("💾 Update System Definitions"):
        download_files_from_github()

    st.divider()
    col_a,col_b = st.columns([0.2,3])
    col_b.markdown("<h3 style='text-align: left; color: black;'>📧 Email Alerts:</h3>", unsafe_allow_html=True)
    send_emails_check = col_a.checkbox('Email Alerts',value=False,label_visibility='collapsed')
    st.session_state['user_email'] = st.text_input("User Email:", value="2021sc04667@wilp.bits-pilani.ac.in",label_visibility="collapsed")

def install_tshark():
    try:
        
        if platform.system() == 'Linux':
            try:

                result = subprocess.run(['tshark', '--version'], capture_output=True, text=True)
                print(result.stdout)
            except FileNotFoundError:      
                subprocess.run(["sudo", "apt", "install", "-yq", "tshark"])

        elif platform.system() == 'Windows':
            try:

                result = subprocess.run(['C:\\Program Files\\Wireshark\\tshark.exe', '--version'], capture_output=True, text=True)
                print(result.stdout)  
            except FileNotFoundError:        
                subprocess.run(['choco', 'install', 'wireshark'])
        
    except Exception as e:
        error_message = "An error occurred: {}".format(e)
        print(error_message)

def packet_capture(run_duration,output_queue):
    wifi_interface = pyshark_test.get_wifi_interface()
    capture = pyshark.LiveCapture(interface=wifi_interface, display_filter='tcp')
    start_time = time.time()

    try:
        for packet in capture.sniff_continuously(packet_count=int(run_duration*60)):
            final_data = pyshark_test.pkt_process(packet)
            # print(final_data)
            output_queue.put(final_data)  # Put the data into the queue for Streamlit to read
            time.sleep(0.1)

            elapsed = time.time() - start_time
            if elapsed >= run_duration * 60:
                break
    except KeyboardInterrupt:
        print("Capture interrupted by user.")

def run_pyshark(run_duration):
    install_tshark()
    st.session_state["attack_cnt"] = 0
    run_date = str('Time ') + str(datetime.fromtimestamp(time.time()).strftime('%d/%m/%Y'))
    attack_cnt_container.markdown(f'<p style="color:white;font-size:36px;'
                                  f'border-radius:2%;">🟢🟢🟢 {st.session_state["attack_cnt"]} compromised data packet 🟢🟢🟢 </p>',
                                  unsafe_allow_html=True)
    df_temp = pd.DataFrame()
    output_queue = multiprocessing.Queue()
    process = multiprocessing.Process(target=packet_capture, args=(run_duration,output_queue,))
    process.start()
    while process.is_alive():
        # Read from the queue and display the data in Streamlit
        if not output_queue.empty():
            final_data, ml_pred, ml_label = output_queue.get()
            #final_data['Prediction'] = ml_pred
            final_data[run_date] = datetime.fromtimestamp(time.time()).strftime('%H-%M-%S-%f')[:-3]

            if len(df_temp)>0:
                df_temp = pd.concat([df_temp,final_data],ignore_index=True)
            else:
                # print("Pyshark concat exception!")
                df_temp = final_data.copy()

            # SHIFT TO FRONT :
            cols_to_front = ['tcp.dstport', 'tcp.srcport', 'ip_dst_host', 'ip_src_host', 'attack_type', 'attack_label', run_date]
            for col in cols_to_front:
                df_temp.insert(0, col, df_temp.pop(col))

            df_container.dataframe(df_temp.iloc[::-1])  # You can use st.code(final_data) if you want to format it as code
            # print(ml_pred)
            if ml_label == 1:  # 1 is ATTACK | 0 is Normal
                st.session_state['attack_cnt'] += 1
            if st.session_state['attack_cnt'] == 0:
                attack_cnt_container.markdown(f'<p style="color:white;font-size:36px;'
                                              f'border-radius:2%;">🟢🟢🟢 {st.session_state["attack_cnt"]} compromised data packet</p>',
                                              unsafe_allow_html=True)
            else:
                attack_cnt_container.markdown(f'<p style="color:white;font-size:36px;'
                                              f'border-radius:2%;">🚨🚨🚨 {st.session_state["attack_cnt"]} compromised data packet</p>',
                                              unsafe_allow_html=True)
            time.sleep(0.02)
        else:
            time.sleep(0.1)  # Sleep briefly to avoid busy-waiting
            curr_datetime = datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S')
    export_file_name = 'pyshark_testing_' + curr_datetime + '.csv'
    test_data_path = os.path.join("artifacts", "logs", export_file_name)
    df_temp.to_csv(test_data_path)

    # SEND ALERT EMAIL:
    if st.session_state['attack_cnt']>0 and send_emails_check:
        filtered_df = df_temp[df_temp['attack_label'] == 1]
        email_data_path = os.path.join("artifacts", "logs", "_attack_detection.csv")
        filtered_df.to_csv(email_data_path)
        current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        email_subject = "⚠️ Alert! IoTShield network attack detection ⚠️"  
        body_html = f"""
                    <html>
                        <body>
                            <p>Hello Team,</p>
                            <p>We have detected an alert from IoT devices. Kindly check the attachment for more details.</p>
                            <p>Date and Time: {current_datetime}</p>
                            <p></p>
                            <p>Thanks</p>
                            <p>IoTShield App</p>
                        </body>
                    </html>
                    """               
        email_status = utils.send_email(email_subject, body_html, email_data_path, st.session_state['user_email'])
        print(email_status)
    process.join()

def delete_files(files_to_delete):
    for file in files_to_delete:
        os.remove(file)
        # st.write(f"Deleted: {file}")

def main():
    
    if col1.button("📶 Live Pyshark Network Packet Capture", help="Live Network Packet Capture"):
        # with st.spinner("Pyshark Executing..."):
        run_pyshark(st.session_state['run_duration'])
        text_to_print = "Live Pyshark Network Packet Capture completed! ✅"
        st.markdown(f'<p style="color:white;font-size:16px;'
                    f'border-radius:2%;">{text_to_print}</p>', unsafe_allow_html=True)

    if col2.button("View Logs", help="Click to view logs"):
        folder_path = os.path.join("artifacts", "logs")
        open_folder(folder_path)
        text_to_print = "Logs Folder Opened"
        st.markdown(f'<p style="color:white;font-size:16px;'
                    f'border-radius:2%;">{text_to_print}</p>', unsafe_allow_html=True)

    if col3.button("Clear Logs", help="Reset logs folder"):
        folder_path = os.path.join("artifacts", "logs")
        files = [f for f in os.listdir(folder_path) if f.endswith('.csv')]
        #print(files)
        delete_files([os.path.join(folder_path, file) for file in files])

        text_to_print = 'All Logs Cleared! 🗑️'
        st.markdown(f'<p style="color:white;font-size:16px;'
                    f'border-radius:2%;">{text_to_print}</p>', unsafe_allow_html=True )

if __name__ == "__main__":
    main()

