package io.mosip.kernel.masterdata.service.impl;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

import io.mosip.kernel.core.dataaccess.exception.DataAccessLayerException;
import io.mosip.kernel.masterdata.constant.WorkingNonWorkingDayErrorCode;
import io.mosip.kernel.masterdata.dto.DayNameAndSeqListDto;
import io.mosip.kernel.masterdata.dto.WeekDaysResponseDto;
import io.mosip.kernel.masterdata.dto.WorkingDaysResponseDto;
import io.mosip.kernel.masterdata.dto.getresponse.WeekDaysDto;
import io.mosip.kernel.masterdata.dto.getresponse.WorkingDaysDto;
import io.mosip.kernel.masterdata.entity.DaysOfWeek;
import io.mosip.kernel.masterdata.entity.RegistrationCenter;
import io.mosip.kernel.masterdata.exception.DataNotFoundException;
import io.mosip.kernel.masterdata.exception.MasterDataServiceException;
import io.mosip.kernel.masterdata.repository.DaysOfWeekListRepo;
import io.mosip.kernel.masterdata.repository.RegWorkingNonWorkingRepo;
import io.mosip.kernel.masterdata.repository.RegistrationCenterRepository;
import io.mosip.kernel.masterdata.service.RegWorkingNonWorkingService;
import io.mosip.kernel.masterdata.utils.ExceptionUtils;

@Service
public class RegWorkingNonWorkingServiceImpl implements RegWorkingNonWorkingService {

	@Autowired
	@Qualifier("workingDaysRepo")
	private RegWorkingNonWorkingRepo workingDaysRepo;

	@Autowired
	@Qualifier("daysOfWeekRepo")
	private DaysOfWeekListRepo daysOfWeekRepo;

	/**
	 * Reference to RegistrationCenterRepository.
	 */
	@Autowired
	private RegistrationCenterRepository registrationCenterRepository;

	@Override
	public WeekDaysResponseDto getWeekDaysList(String regCenterId, String langCode) {

		List<WeekDaysDto> weekdayList = null;
		List<DayNameAndSeqListDto> nameSeqList = null;
		WeekDaysResponseDto weekdays = new WeekDaysResponseDto();
		RegistrationCenter registrationCenter = null;

		Objects.requireNonNull(regCenterId);
		Objects.requireNonNull(langCode);

		try {
			nameSeqList = workingDaysRepo.findByregistrationCenterIdAndlanguagecodeForWeekDays(regCenterId, langCode);
			registrationCenter = registrationCenterRepository.findByIdAndLangCode(regCenterId, langCode);
		} catch (DataAccessException | DataAccessLayerException e) {
			throw new MasterDataServiceException(
					WorkingNonWorkingDayErrorCode.WORKING_DAY_TABLE_NOT_ACCESSIBLE.getErrorCode(),
					WorkingNonWorkingDayErrorCode.WORKING_DAY_TABLE_NOT_ACCESSIBLE.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}
		if (registrationCenter == null) {
			throw new DataNotFoundException(WorkingNonWorkingDayErrorCode.REGISTRATION_CENTER_NOT_FOUND.getErrorCode(),
					WorkingNonWorkingDayErrorCode.REGISTRATION_CENTER_NOT_FOUND.getErrorMessage());
		} else {
			if (nameSeqList != null && !nameSeqList.isEmpty()) {

				nameSeqList.sort((d1, d2) -> d1.getDaySeq() - d2.getDaySeq());
				weekdayList = nameSeqList.stream().map(nameSeq -> {
					WeekDaysDto dto = new WeekDaysDto();
					dto.setLanguageCode(langCode);
					dto.setName(nameSeq.getName());
					dto.setOrder(nameSeq.getDaySeq());
					return dto;
				}).collect(Collectors.toList());
				weekdays.setWeekdays(weekdayList);

			} else {
				throw new DataNotFoundException(
						WorkingNonWorkingDayErrorCode.WEEK_DAY_DATA_FOUND_EXCEPTION.getErrorCode(),
						WorkingNonWorkingDayErrorCode.WEEK_DAY_DATA_FOUND_EXCEPTION.getErrorMessage());
			}

		}

		return weekdays;
	}

	@Override
	public WorkingDaysResponseDto getWorkingDays(String regCenterId, String langCode) {

		List<WorkingDaysDto> workingDayList = null;
		WorkingDaysResponseDto responseDto = new WorkingDaysResponseDto();
		Objects.requireNonNull(regCenterId);
		Objects.requireNonNull(langCode);
		RegistrationCenter registrationCenter = null;
		try {
			workingDayList = workingDaysRepo.findByregistrationCenterIdAndlangCodeForWorkingDays(regCenterId, langCode);
			registrationCenter = registrationCenterRepository.findByIdAndLangCode(regCenterId, langCode);
		} catch (DataAccessException | DataAccessLayerException e) {
			throw new MasterDataServiceException(
					WorkingNonWorkingDayErrorCode.WORKING_DAY_TABLE_NOT_ACCESSIBLE.getErrorCode(),
					WorkingNonWorkingDayErrorCode.WORKING_DAY_TABLE_NOT_ACCESSIBLE.getErrorMessage()
							+ ExceptionUtils.parseException(e));
		}
		if (registrationCenter == null) {
			throw new DataNotFoundException(WorkingNonWorkingDayErrorCode.REGISTRATION_CENTER_NOT_FOUND.getErrorCode(),
					WorkingNonWorkingDayErrorCode.REGISTRATION_CENTER_NOT_FOUND.getErrorMessage());
		} else {
			// Fetch from DB.
			if (workingDayList != null && !workingDayList.isEmpty()) {
				responseDto.setWorkingdays(workingDayList);
			}
			// Fetch from global level .
			else {
				List<DaysOfWeek> globalDaysList = daysOfWeekRepo.findByAllGlobalWorkingTrue(langCode);
				if (globalDaysList != null && !globalDaysList.isEmpty()) {
					workingDayList = globalDaysList.stream().map(day -> {
						WorkingDaysDto globalWorkingDay = new WorkingDaysDto();
						globalWorkingDay.setDayCode(day.getCode());
						globalWorkingDay.setGlobalWorking(day.isGlobalWorking());
						globalWorkingDay.setLanguagecode(day.getLangCode());
						globalWorkingDay.setName(day.getName());
						return globalWorkingDay;
					}).collect(Collectors.toList());

					responseDto.setWorkingdays(workingDayList);
				} else {
					throw new DataNotFoundException(
							WorkingNonWorkingDayErrorCode.WORKING_DAY_DATA_FOUND_EXCEPTION.getErrorCode(),
							WorkingNonWorkingDayErrorCode.WORKING_DAY_DATA_FOUND_EXCEPTION.getErrorMessage());
				}

			}
		}

		return responseDto;
	}

}
