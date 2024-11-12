use std::io::Cursor;

use symphonia::core::{
    codecs::DecoderOptions,
    formats::FormatOptions, 
    io:: MediaSourceStream, 
    meta::MetadataOptions, 
    probe::Hint
};

pub fn get_audio_length(stream: Cursor<Vec<u8>>) -> usize {
    let mss = MediaSourceStream::new(Box::new(stream), Default::default());
    let hint = Hint::new();
    // hint.with_extension(file_type);

    let meta_opts: MetadataOptions = Default::default();
    let fmt_opts: FormatOptions = Default::default();

    let probe = symphonia::default::get_probe()
        .format(&hint, mss, &fmt_opts, &meta_opts)
        .expect("audio format error!");


    let decoder = symphonia::default::get_codecs().make(&probe.format.default_track().unwrap().codec_params, &DecoderOptions { verify: false }).unwrap();
    decoder.codec_params().time_base.unwrap().calc_time(4728960).seconds as usize
}

