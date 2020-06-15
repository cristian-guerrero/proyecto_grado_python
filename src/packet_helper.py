
from scapy.layers.http import HTTPRequest, HTTPResponse


class Packet_helper():

  def __init__(self, packet):
    self.json_types = (dict, list, str, int, float, bool)
    self.packet = packet

  def __call__(self):
    output = []
    for layer in self.get_packet_layers():
      layer_name = layer.name if layer.name else layer.__name__

      if   self.is_black_layer(layer_name) : continue
      # output.append({layer_name: self.})
      output.append({layer_name: self._serialize_fields(layer, {})})
    return output


  def _serialize_fields(self, layer, serialized_fields={}):
    if hasattr(layer, "fields_desc"):
      for field in layer.fields_desc:
        self._extract_fields(layer, field, serialized_fields)
    return serialized_fields

  def _extract_fields(self, layer, field, extracted={}):
    value = layer.__getattr__(field.name)
    if type(value) in self.json_types and \
        not hasattr(value, "fields_desc") and \
        not type(value) == list:
      extracted.update({field.name: value})
    else:
      local_serialized = {}
      extracted.update({field.name: local_serialized})
      self._serialize_fields(field, local_serialized)


  def get_packet_layers(self):
    counter = 0
    while True:
      layer = self.packet.getlayer(counter)
      if layer is None:
        break

      yield layer
      counter += 1

  def is_black_layer (self, layer_name):
    
    if layer_name == 'UDP' or layer_name ==  'Ethernet' or layer_name == 'Padding': return True
    # if layer_name == 'IP Option Router Alert': return True
    '''
    if layer_name == 'DNS Resource Record' or layer_name == 'DNS' or layer_name == 'DNS EDNS0 TLV' : return True
    if layer_name == 'DNS Question Record' or layer_name == 'DNS SRV Resource Record': return True
    if layer_name == 'DNS OPT Resource Record' or layer_name == 'DNS NSEC Resource Record': return True
    '''
    return False
