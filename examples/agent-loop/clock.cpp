time_t ACME::Aurora::Core::Clock::getTimeOffset()
{
    return *reinterpret_cast<volatile time_t *>(&ACME::Aurora::Core::Clock::time_offset);
}
