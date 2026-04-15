import React, { useState, useEffect, useRef } from "react";
import { ImCross } from "react-icons/im";
import { IoIosSend } from "react-icons/io";
import { ThreeDots } from "react-loader-spinner";
import { IoChatbubbles } from "react-icons/io5";
import { FaUserCircle } from "react-icons/fa";
import { TbMessageChatbotFilled } from "react-icons/tb";
import ReactMarkDown from "react-markdown";
import { notifyError } from "./Notification";

function Chatbot({ messages, setMessages, onClose }) {
  const MessageContent = ({ msg }) => {
    const [copyText, setCopyText] = useState("Copy");
    const copyToClipboard = (text) => {
      navigator.clipboard.writeText(text);
      setCopyText("Copied!");
      setTimeout(() => {
        setCopyText("Copy");
      }, 2000);
    };

    return (
      <div className="prose prose-sm max-w-none">
        <ReactMarkDown
          components={{
            code({ node, inline, className, children, ...props }) {
              const match = /language-(\w+)/.exec(className || "");
              const codeContent = String(children).replace(/\n$/, "");

              if (!inline && match) {
                return (
                  <div className="relative">
                    <button
                      onClick={() => copyToClipboard(codeContent)}
                      className="absolute right-2 top-2 text-xs bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded"
                    >
                      {copyText}
                    </button>
                    <pre className="mt-0 bg-gray-800 rounded-md p-4 overflow-x-auto text-sm text-white">
                      <code className={`${className} font-mono`} {...props}>
                        {children}
                      </code>
                    </pre>
                  </div>
                );
              }
              return (
                <code
                  className="text-red-500 bg-gray-100 px-1.5 py-0.5 rounded text-sm"
                  {...props}
                >
                  {children}
                </code>
              );
            },
          }}
        >
          {msg.text}
        </ReactMarkDown>
      </div>
    );
  };
  const [message, setMessage] = useState("");
  // const [messages, setMessages] = useState([
  //   { sender: "bot", text: "Hello! How can I assist you today?" },
  // ]);
  const endOfMessagesRef = useRef(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (endOfMessagesRef.current) {
      endOfMessagesRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages]);

  const handleSend = async () => {
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    if (message.trim()) {
      setLoading(true);
      const payload = {
        logs_type: "chatbot",
        query: message.trim(),
      };
      const userMessage = { sender: "user", text: message };
      setMessages((prev) => [...prev, userMessage]);
      setMessage("");

      try {
        const response = await fetch(`${backend_url}/api/chatbot`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const result = await response.json();
        // console.log("result: ", result);

        if (result.status === "ok") {
          setMessages((prev) => {
            return [...prev, { sender: "bot", text: result.chatbot_response }];
          });
        }
      } catch (err) {
        console.log("error: ", err);
        notifyError(err);
      } finally {
        setLoading(false);
      }
    }
  };

  return (
    <div className="chatbot-container fixed bottom-12 right-0 m-7 w-[30%] h-[75%] shadow-xl shadow-indigo-500/10 bg-slate-50 dark:bg-slate-900 rounded-xl border border-indigo-200 dark:border-slate-700 flex flex-col">
      <div className="chatbot-header flex justify-between items-center bg-gradient-to-r from-indigo-600 to-purple-600 dark:bg-slate-900/95 border-indigo-200 dark:border-slate-700   p-4 rounded-t-xl">
        <div className="inline-block text-white text-xl">
          <IoChatbubbles />
        </div>
        <div className="text-white font-bold text-base">Chatbot</div>
        <button className="text-white" onClick={onClose}>
          <ImCross />
        </button>
      </div>

      <div className="chatbot-content flex-1 overflow-y-auto pt-4 space-y-2 pr-1 flex flex-col p-3 bg-slate-50/80 dark:bg-slate-800/80 dark:bg-gradient-to-r dark:from-slate-900/80 dark:to-slate-700/80">
        {messages.map((msg, index) => (
          <div
            key={index}
            className={`flex items-start gap-2 ${
              msg.sender === "bot" ? "justify-start" : "justify-end"
            } items-start gap-2`}
          >
            {msg.sender === "bot" && (
              <>
                {/* <TbMessageChatbotFilled className="text-indigo-500 dark:text-gray-500 text-xl mt-2" /> */}
                <img
                  src="Chatbot_logo.png"
                  className="pt-2 block self-end"
                  width={30}
                ></img>
              </>
            )}
            <div
              className={`flex flex-col items-${
                msg.sender === "bot" ? "start" : "end"
              } max-w-[80%]`}
            >
              <div
                className={`p-2 rounded-t-2xl break-words ${
                  msg.sender === "bot"
                    ? "bg-indigo-100 dark:bg-gray-100 rounded-br-2xl self-start max-w-[250px]"
                    : "bg-indigo-200 dark:bg-gray-300 rounded-bl-2xl self-end max-w-[200px]"
                }`}
              >
                <MessageContent msg={msg} />
              </div>
            </div>
            {msg.sender === "user" && (
              <FaUserCircle className="text-indigo-500 dark:text-gray-300 self-end text-xl mt-2" />
            )}
          </div>
        ))}
        {loading && (
          <div className="self-start p-2 rounded inline-block max-w-[80%]">
            <ThreeDots
              visible={true}
              height="50"
              width="50"
              color="#9E9E9E"
              radius="9"
              ariaLabel="three-dots-loading"
            />
          </div>
        )}
        <div ref={endOfMessagesRef} />
      </div>
      <div className="pt-2 flex items-center space-x-2 p-3 dark:bg-slate-800/80 dark:bg-gradient-to-r dark:from-slate-900/80 dark:to-slate-700/80 rounded-b-xl">
        <input
          type="text"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onKeyDown={(e) => {
            if (!loading && e.key === "Enter") {
              e.preventDefault();
              handleSend();
            }
          }}
          className="w-full p-2 rounded-xl border border-gray-300 focus:outline-none focus:border-indigo-500"
          placeholder="Type your message..."
        />
        <button
          onClick={handleSend}
          className={`!bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-4 py-[10px] h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 ${
            loading ? "opacity-50 cursor-not-allowed" : ""
          }`}
        >
          <IoIosSend size={20} />
        </button>
      </div>
    </div>
  );
}

export default Chatbot;
