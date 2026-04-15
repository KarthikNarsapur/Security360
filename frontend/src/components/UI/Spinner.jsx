import { Spin } from "antd";
import { LoadingOutlined } from "@ant-design/icons";

const antIcon = (
  <LoadingOutlined
    style={{ fontSize: 16 }}
    spin
    className="text-black drop-shadow-sm"
  />
);

const Spinner = () => <Spin indicator={antIcon} />;

export default Spinner;
