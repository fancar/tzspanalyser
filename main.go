package tzspanalyser

import (
    "encoding/hex"
    "errors"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/klauspost/oui"
    "github.com/rs/tzsp"
    //    "net"
    //  "fmt"
)

var (
    OUI_db oui.StaticDB
)

func OpenOuiDb(filename string) error {
    db, err := oui.OpenStaticFile(filename)
    if err != nil {
        return err
    }

    OUI_db = db
    return nil
}

func VendorByMac(mac []byte) (string, error) {

    hw := oui.HardwareAddr{mac[0], mac[1], mac[2]}
    entry, err := OUI_db.LookUp(hw)

    if err == oui.ErrNotFound {
        return "unknown", nil

    } else if err != nil {
        return "no data", err
    } else {
        return entry.Manufacturer, nil
    }
}

func Parse(packet []uint8) (map[string]interface{}, error) {
    result := map[string]interface{}{}
    p, err := tzsp.Parse(packet)
    if err != nil {
        return result, err
    }

    if p.Header.Proto.String() != "ProtoIEEE80211" {
        return result, errors.New("Unknown protocol incapsulated: " + p.Header.Proto.String())
    }

    result = RadioTap(p)

    if result["sensor_id"] == "" || result["sensor_id"] == nil {
        return result, errors.New("No sensor-id in RadioTap. Might be some old firmware?")
    }

    return result, nil

}

func RadioTap(p tzsp.Packet) map[string]interface{} {
    // meta header. Look through radiotap interface data that contains in tzsp header
    //fmt.Println("Dot11 flame have been detecded")
    result := map[string]interface{}{"dot11header": p.Data}
    for _, t := range p.Tags {
        //fmt.Println("radio_tap:",t.Type.String(),t.Data)
        switch t.Type.String() {
        case "TagWLANRadioHDRSerial":
            result["sensor_id"] = hex.EncodeToString(t.Data)
        case "TagRawRSSI":
            result["RSSI"] = int64(t.Data[0]) - 256
        case "TagDataRate":
            result["data_rate"] = int64(t.Data[0])
        case "TagRXChannel":
            result["rx_channel"] = int64(t.Data[0])
        }
    }
    return result
}

func ParseDot11(data []byte) layers.Dot11 {
    // wi-fi header is parsing by gopacket layers

    var Dot11 layers.Dot11 //Dot11
    //var CtrlBlockAck layers.Dot11CtrlBlockAck
    //var Ctrl layers.Dot11Ctrl
    Decodedlayers := []gopacket.LayerType{}
    parser := gopacket.NewDecodingLayerParser(layers.LayerTypeDot11, &Dot11) //, &CtrlBlockAck, &Ctrl
    //fmt.Println(parser)
    parser.DecodeLayers(data, &Decodedlayers) // packet.Data()

    // if err != nil {
    //     fmt.Println("Trouble decoding layers: ", err)
    // }

    return Dot11
}

func BitDisabled(data byte, position uint) bool {
    return data&(1<<position) == 0
}

func MacIsUnicast(mac []byte) bool {
    return BitDisabled(mac[0], 0)
}

func MacAUIisUnique(mac []byte) bool {
    return BitDisabled(mac[0], 1)
}
