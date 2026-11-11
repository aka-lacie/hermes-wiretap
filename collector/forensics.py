"""Bounded, exact first-divergence evidence for cache-prefix diagnostics.

Linear prefix/suffix scans, not an unbounded sequence diff. Payload-bearing image
and attachment fields become size descriptions; their base64 is never returned.
"""
from __future__ import annotations

import json

_MISSING = object()
CONTEXT = 80
CHANGE_LIMIT = 160


def _path(parent, key):
    return f'{parent}[{key}]' if isinstance(key, int) else f'{parent}.{key}' if parent else str(key)


def first_difference(a, b, path='', depth=0):
    if depth > 48 or type(a) is not type(b):
        return path, a, b
    if isinstance(a, dict):
        for key in a:
            if key not in b:
                return _path(path, key), a[key], _MISSING
            diff = first_difference(a[key], b[key], _path(path, key), depth+1)
            if diff is not None:
                return diff
        for key in b:
            if key not in a:
                return _path(path, key), _MISSING, b[key]
        if list(a) != list(b):
            return path + ' (key order)', a, b
    elif isinstance(a, list):
        for i in range(min(len(a), len(b))):
            diff = first_difference(a[i], b[i], _path(path, i), depth+1)
            if diff is not None:
                return diff
        if len(a) != len(b):
            i = min(len(a), len(b))
            return _path(path, i), a[i] if i<len(a) else _MISSING, b[i] if i<len(b) else _MISSING
    elif a != b:
        return path, a, b
    return None


def _payload(key, value):
    return isinstance(value, str) and (key in ('data','b64_json','file_data','encrypted_content') or value.startswith('data:'))


def _safe(value, key='', depth=0):
    if depth > 48:
        return '[nested content]'
    if _payload(key, value):
        return f'[payload: {len(value):,} encoded chars]'
    if isinstance(value, dict):
        return {k:_safe(v,k,depth+1) for k,v in value.items()}
    if isinstance(value, list):
        return [_safe(v,key,depth+1) for v in value]
    return value


def _text(value, path):
    if value is _MISSING:
        return '[absent]'
    key = path.rsplit('.',1)[-1]
    if _payload(key,value):
        return f'[payload: {len(value):,} encoded chars]'
    return value if isinstance(value,str) else json.dumps(_safe(value),ensure_ascii=False,separators=(',', ':'))


def media_counts(obj):
    images = attachments = encoded = 0
    stack = [obj]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            kind = value.get('type')
            inline = value.get('inlineData') or value.get('inline_data')
            if kind in ('image','image_url','input_image','output_image'):
                images += 1
            elif isinstance(inline,dict) and str(inline.get('mimeType') or inline.get('mime_type') or '').startswith('image/'):
                images += 1
            elif kind in ('file','input_file','document'):
                attachments += 1
            for key,item in value.items():
                if _payload(key,item):
                    encoded += len(item)
                elif isinstance(item,(dict,list)):
                    stack.append(item)
        elif isinstance(value,list):
            stack.extend(value)
    return dict(images=images,attachments=attachments,payload_chars=encoded)


def window(a: str, b: str):
    start = 0
    limit = min(len(a),len(b))
    while start<limit and a[start]==b[start]:
        start += 1
    end = 0
    while end<limit-start and a[len(a)-end-1]==b[len(b)-end-1]:
        end += 1
    def side(text):
        stop = len(text)-end
        changed = text[start:stop]
        return dict(prefix=text[max(0,start-CONTEXT):start],change=changed[:CHANGE_LIMIT],
                    suffix=text[stop:stop+CONTEXT],omitted_prefix=max(0,start-CONTEXT),
                    omitted_change=max(0,len(changed)-CHANGE_LIMIT),omitted_suffix=max(0,len(text)-stop-CONTEXT),
                    changed_chars=len(changed))
    return dict(offset=start,line=a.count('\n',0,start)+1,before=side(a),after=side(b))


def describe(a, b, path='item'):
    found = first_difference(a,b,path)
    if found is None:
        return None
    location, old, new = found
    old_text, new_text = _text(old,location), _text(new,location)
    opaque_replacement = old_text == new_text and old != new
    if opaque_replacement:
        old_text, new_text = '[previous encoded payload]', '[replacement encoded payload]'
    result: dict = dict(v=2,path=location,**window(old_text,new_text))
    prior, current = media_counts(a), media_counts(b)
    result['media'] = {'before':prior,'after':current}
    notes=[]
    for key,label in (('images','image'),('attachments','attachment')):
        delta=current[key]-prior[key]
        if delta:
            notes.append(f'{abs(delta):,} {label}{"s" if abs(delta)!=1 else ""} {"added" if delta>0 else "removed"}')
    delta=current['payload_chars']-prior['payload_chars']
    if delta:
        notes.append(f'{abs(delta):,} encoded payload chars {"added" if delta>0 else "removed"}')
    result['summary']='; '.join(notes) or ('Encoded payload replaced (same length); content omitted' if opaque_replacement else '')
    return result
